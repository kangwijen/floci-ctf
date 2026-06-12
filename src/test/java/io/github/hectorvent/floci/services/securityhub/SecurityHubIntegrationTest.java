package io.github.hectorvent.floci.services.securityhub;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
class SecurityHubIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = "AWSSecurityHub.";
    private static final String PRODUCT_ARN =
            "arn:aws:securityhub:us-east-1:000000000000:product/000000000000/default";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void securityHubFindingsLifecycle() {
        given()
                .header("X-Amz-Target", TARGET_PREFIX + "DescribeHub")
                .contentType(CONTENT_TYPE)
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(404);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "EnableSecurityHub")
                .contentType(CONTENT_TYPE)
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "DescribeHub")
                .contentType(CONTENT_TYPE)
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("HubArn", startsWith("arn:aws:securityhub:"))
                .body("AutoEnableControls", equalTo(true))
                .body("ControlFindingGenerator", equalTo("SECURITY_CONTROL"))
                .body("SubscribedAt", startsWith("20"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "BatchImportFindings")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Findings": [
                                {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": "finding-high-open",
                                    "ProductArn": "%s",
                                    "GeneratorId": "custom-generator",
                                    "AwsAccountId": "000000000000",
                                    "Region": "us-east-1",
                                    "Title": "Open security group",
                                    "Description": "Port 22 is open to the world",
                                    "Severity": {"Label": "HIGH", "Normalized": 70},
                                    "Compliance": {"Status": "FAILED"},
                                    "Workflow": {"Status": "NEW"}
                                },
                                {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": "finding-low-passed",
                                    "ProductArn": "%s",
                                    "GeneratorId": "custom-generator",
                                    "AwsAccountId": "000000000000",
                                    "Region": "us-east-1",
                                    "Title": "Encryption enabled",
                                    "Description": "S3 bucket has encryption",
                                    "Severity": {"Label": "LOW", "Normalized": 10},
                                    "Compliance": {"Status": "PASSED"},
                                    "Workflow": {"Status": "NEW"}
                                }
                            ]
                        }
                        """.formatted(PRODUCT_ARN, PRODUCT_ARN))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("SuccessCount", equalTo(2))
                .body("FailedCount", equalTo(0));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "GetFindings")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Filters": {
                                "SeverityLabel": [
                                    {"Comparison": "EQUALS", "Value": "HIGH"}
                                ]
                            }
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Findings", hasSize(1))
                .body("Findings[0].Id", equalTo("finding-high-open"))
                .body("Findings[0].Severity.Label", equalTo("HIGH"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "GetFindings")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Filters": {
                                "ProductArn": [
                                    {"Comparison": "EQUALS", "Value": "%s"}
                                ],
                                "ComplianceStatus": [
                                    {"Comparison": "EQUALS", "Value": "PASSED"}
                                ]
                            }
                        }
                        """.formatted(PRODUCT_ARN))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Findings", hasSize(1))
                .body("Findings[0].Id", equalTo("finding-low-passed"))
                .body("Findings[0].Compliance.Status", equalTo("PASSED"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "BatchUpdateFindings")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "FindingIdentifiers": [
                                {
                                    "Id": "finding-high-open",
                                    "ProductArn": "%s"
                                }
                            ],
                            "Workflow": {"Status": "RESOLVED"},
                            "Severity": {"Label": "MEDIUM", "Normalized": 40}
                        }
                        """.formatted(PRODUCT_ARN))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("ProcessedFindings", hasSize(1))
                .body("UnprocessedFindings", hasSize(0));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "GetFindings")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Filters": {
                                "SeverityLabel": [
                                    {"Comparison": "EQUALS", "Value": "MEDIUM"}
                                ]
                            }
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Findings", hasSize(1))
                .body("Findings[0].Workflow.Status", equalTo("RESOLVED"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "ListEnabledProductsForImport")
                .contentType(CONTENT_TYPE)
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("ProductSubscriptions", hasSize(0));
    }
}
