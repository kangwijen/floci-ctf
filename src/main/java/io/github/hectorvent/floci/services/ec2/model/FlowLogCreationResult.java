package io.github.hectorvent.floci.services.ec2.model;

import java.util.ArrayList;
import java.util.List;

public class FlowLogCreationResult {

    private final List<String> flowLogIds = new ArrayList<>();
    private final List<FlowLogUnsuccessfulItem> unsuccessful = new ArrayList<>();

    public List<String> getFlowLogIds() { return flowLogIds; }

    public List<FlowLogUnsuccessfulItem> getUnsuccessful() { return unsuccessful; }
}
