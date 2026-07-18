package io.github.hectorvent.floci.services.autoscaling;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.autoscaling.model.AsgInstance;
import io.github.hectorvent.floci.services.autoscaling.model.AutoScalingGroup;
import io.github.hectorvent.floci.services.autoscaling.model.LaunchConfiguration;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.Reservation;
import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.ssm.SsmCommandService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * E-FO-02: AutoScaling reconciler must authorize EC2 / ELBv2 / SSM side effects in-process.
 */
@Tag("security-regression")
class AutoScalingReconcilerAuthorizerTest {

    private static final String REGION = "us-east-1";
    private static final String ASG_ARN =
            "arn:aws:autoscaling:us-east-1:000000000000:autoScalingGroup:asg-1";
    private static final String TG_ARN =
            "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/app/abc";
    private static final String PROFILE_ARN =
            "arn:aws:iam::000000000000:instance-profile/asg-profile";

    private AutoScalingService asgService;
    private Ec2Service ec2Service;
    private ElbV2Service elbV2Service;
    private SsmCommandService ssmCommandService;
    private InProcessTargetAuthorizer targetAuthorizer;
    private AutoScalingReconciler reconciler;

    @BeforeEach
    void setUp() {
        asgService = mock(AutoScalingService.class);
        ec2Service = mock(Ec2Service.class);
        elbV2Service = mock(ElbV2Service.class);
        ssmCommandService = mock(SsmCommandService.class);
        targetAuthorizer = mock(InProcessTargetAuthorizer.class);
        reconciler = new AutoScalingReconciler(
                asgService, ec2Service, elbV2Service, ssmCommandService, targetAuthorizer);
    }

    @Test
    void scaleOutAuthorizesBeforeRunInstances() {
        AutoScalingGroup asg = baseAsg(1);
        asg.setLaunchConfigurationName("app-lc");
        LaunchConfiguration lc = new LaunchConfiguration();
        lc.setLaunchConfigurationName("app-lc");
        lc.setImageId("ami-123");
        lc.setInstanceType("t3.micro");
        lc.setIamInstanceProfile(PROFILE_ARN);
        when(asgService.describeLaunchConfigurations(REGION, List.of("app-lc")))
                .thenReturn(List.of(lc));
        Instance launched = new Instance();
        launched.setInstanceId("i-new");
        Reservation reservation = new Reservation();
        reservation.setInstances(List.of(launched));
        when(ec2Service.runInstances(anyString(), anyString(), anyString(), anyInt(), anyInt(),
                any(), anyList(), any(), any(), anyList(), any(), anyString(), eq(false)))
                .thenReturn(reservation);

        reconciler.reconcile(asg);

        verify(targetAuthorizer).authorizeAutoScalingRunInstances(
                ASG_ARN, REGION, "000000000000", PROFILE_ARN);
        verify(ec2Service).runInstances(eq(REGION), eq("ami-123"), eq("t3.micro"),
                eq(1), eq(1), isNull(), eq(List.of()), isNull(), isNull(),
                anyList(), isNull(), eq(PROFILE_ARN), eq(false));
    }

    @Test
    void scaleOutSkipsRunInstancesWhenAuthorizerDenies() {
        AutoScalingGroup asg = baseAsg(1);
        asg.setLaunchConfigurationName("app-lc");
        LaunchConfiguration lc = new LaunchConfiguration();
        lc.setLaunchConfigurationName("app-lc");
        lc.setImageId("ami-123");
        lc.setInstanceType("t3.micro");
        when(asgService.describeLaunchConfigurations(REGION, List.of("app-lc")))
                .thenReturn(List.of(lc));
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(targetAuthorizer).authorizeAutoScalingRunInstances(
                        eq(ASG_ARN), eq(REGION), eq("000000000000"), isNull());

        reconciler.reconcile(asg);

        verify(ec2Service, never()).runInstances(anyString(), anyString(), anyString(),
                anyInt(), anyInt(), any(), anyList(), any(), any(), anyList(), any(), any(),
                org.mockito.ArgumentMatchers.anyBoolean());
        assertTrue(asg.getInstances().isEmpty());
    }

    @Test
    void scaleInAuthorizesBeforeTerminateAndDeregister() {
        AutoScalingGroup asg = baseAsg(0);
        AsgInstance inService = new AsgInstance();
        inService.setInstanceId("i-old");
        inService.setLifecycleState("InService");
        asg.getInstances().add(inService);
        asg.getTargetGroupARNs().add(TG_ARN);
        when(ec2Service.isInstanceContainerRunning("i-old")).thenReturn(true);

        reconciler.reconcile(asg);

        verify(targetAuthorizer).authorizeAutoScalingDeregisterTargets(ASG_ARN, TG_ARN, REGION);
        verify(targetAuthorizer).authorizeAutoScalingTerminateInstances(
                ASG_ARN, REGION, "000000000000", List.of("i-old"));
        verify(elbV2Service).deregisterTargets(eq(REGION), eq(TG_ARN), anyList());
        verify(ec2Service).terminateInstances(REGION, List.of("i-old"));
    }

    @Test
    void staleInstanceRemovalAuthorizesSsmFailInvocations() {
        AutoScalingGroup asg = baseAsg(0);
        AsgInstance stale = new AsgInstance();
        stale.setInstanceId("i-stale");
        stale.setLifecycleState("InService");
        asg.getInstances().add(stale);
        when(ec2Service.isInstanceContainerRunning("i-stale")).thenReturn(false);
        when(ssmCommandService.failActiveInvocationsForInstances(
                eq(REGION), eq(Set.of("i-stale")), eq("Undeliverable"))).thenReturn(1);

        reconciler.reconcile(asg);

        verify(targetAuthorizer).authorizeAutoScalingSsmFailInvocations(
                ASG_ARN, REGION, "000000000000", List.of("i-stale"));
        verify(ssmCommandService).failActiveInvocationsForInstances(
                REGION, Set.of("i-stale"), "Undeliverable");
        assertEquals(0, asg.getInstances().size());
    }

    private static AutoScalingGroup baseAsg(int desired) {
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion(REGION);
        asg.setAutoScalingGroupName("app-asg");
        asg.setAutoScalingGroupArn(ASG_ARN);
        asg.setDesiredCapacity(desired);
        asg.setAvailabilityZones(List.of("us-east-1a"));
        return asg;
    }
}
