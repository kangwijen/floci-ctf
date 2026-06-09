package io.github.hectorvent.floci.services.dynamodb;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * {@code dynamodb:PartiQL*} scoped per statement in {@code BatchExecuteStatement}.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DynamoDbBatchExecuteStatementScopedIntegrationTest {

    private static final String DYNAMODB_CONTENT_TYPE = "application/x-amz-json-1.0";
    private static final String ALLOWED_TABLE = "ctf-batch-partiql-allowed";
    private static final String DECOY_TABLE = "ctf-batch-partiql-decoy";

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-batch-partiql-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "dynamodb");

        createTable(rootAuth, ALLOWED_TABLE);
        createTable(rootAuth, DECOY_TABLE);

        putItem(rootAuth, ALLOWED_TABLE, "lab-flag", "allowed-value");
        putItem(rootAuth, DECOY_TABLE, "decoy-flag", "decoy-value");

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":["dynamodb:PartiQLSelect"],
               "Resource":"arn:aws:dynamodb:us-east-1:%s:table/%s"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT, ALLOWED_TABLE);
        CtfLabIamTestSupport.putUserPolicy(user, "partiql-batch-read-one", policy);
    }

    private static void createTable(String auth, String tableName) {
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", "DynamoDB_20120810.CreateTable")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "TableName": "%s",
                          "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                          "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                          "BillingMode": "PAY_PER_REQUEST"
                        }""".formatted(tableName))
                .when().post("/")
                .then().statusCode(200);
    }

    private static void putItem(String auth, String tableName, String pk, String value) {
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", "DynamoDB_20120810.PutItem")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "TableName": "%s",
                          "Item": {
                            "pk": {"S": "%s"},
                            "value": {"S": "%s"}
                          }
                        }""".formatted(tableName, pk, value))
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void batchExecuteStatementAllAllowedTables() {
        given()
                .header("Authorization", playerAuth())
                .header("X-Amz-Target", "DynamoDB_20120810.BatchExecuteStatement")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "Statements": [
                            {
                              "Statement": "SELECT * FROM \\"%s\\" WHERE pk = ?",
                              "Parameters": [{"S": "lab-flag"}]
                            },
                            {
                              "Statement": "SELECT * FROM \\"%s\\" WHERE pk = ?",
                              "Parameters": [{"S": "lab-flag"}]
                            }
                          ]
                        }""".formatted(ALLOWED_TABLE, ALLOWED_TABLE))
                .when().post("/")
                .then().statusCode(200)
                .body("Responses[0].Item.value.S", equalTo("allowed-value"))
                .body("Responses[1].Item.value.S", equalTo("allowed-value"));
    }

    @Test
    void batchExecuteStatementDeniedWhenAnyTableNotAllowed() {
        given()
                .header("Authorization", playerAuth())
                .header("X-Amz-Target", "DynamoDB_20120810.BatchExecuteStatement")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "Statements": [
                            {
                              "Statement": "SELECT * FROM \\"%s\\" WHERE pk = ?",
                              "Parameters": [{"S": "lab-flag"}]
                            },
                            {
                              "Statement": "SELECT * FROM \\"%s\\" WHERE pk = ?",
                              "Parameters": [{"S": "decoy-flag"}]
                            }
                          ]
                        }""".formatted(ALLOWED_TABLE, DECOY_TABLE))
                .when().post("/")
                .then().statusCode(403);
    }

    private String playerAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "dynamodb");
    }
}
