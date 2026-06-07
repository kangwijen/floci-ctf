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
 * {@code dynamodb:GetItem} and {@code dynamodb:Query} scoped via {@code TableName} JSON.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DynamoDbGetItemQueryScopedIntegrationTest {

    private static final String DYNAMODB_CONTENT_TYPE = "application/x-amz-json-1.0";
    private static final String ALLOWED_TABLE = "ctf-lab-allowed-table";
    private static final String DECOY_TABLE = "ctf-lab-decoy-table";

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-dynamodb-player";
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
              {"Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:Query"],
               "Resource":"arn:aws:dynamodb:us-east-1:%s:table/%s"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT, ALLOWED_TABLE);
        CtfLabIamTestSupport.putUserPolicy(user, "ddb-read-one", policy);
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
    void getItemAllowedTable() {
        given()
                .header("Authorization", playerAuth())
                .header("X-Amz-Target", "DynamoDB_20120810.GetItem")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "TableName": "%s",
                          "Key": {"pk": {"S": "lab-flag"}}
                        }""".formatted(ALLOWED_TABLE))
                .when().post("/")
                .then().statusCode(200)
                .body("Item.value.S", equalTo("allowed-value"));
    }

    @Test
    void getItemDecoyTableDenied() {
        given()
                .header("Authorization", playerAuth())
                .header("X-Amz-Target", "DynamoDB_20120810.GetItem")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "TableName": "%s",
                          "Key": {"pk": {"S": "decoy-flag"}}
                        }""".formatted(DECOY_TABLE))
                .when().post("/")
                .then().statusCode(403);
    }

    @Test
    void queryAllowedTable() {
        given()
                .header("Authorization", playerAuth())
                .header("X-Amz-Target", "DynamoDB_20120810.Query")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "TableName": "%s",
                          "KeyConditionExpression": "pk = :pk",
                          "ExpressionAttributeValues": {":pk": {"S": "lab-flag"}}
                        }""".formatted(ALLOWED_TABLE))
                .when().post("/")
                .then().statusCode(200)
                .body("Items[0].value.S", equalTo("allowed-value"));
    }

    @Test
    void queryDecoyTableDenied() {
        given()
                .header("Authorization", playerAuth())
                .header("X-Amz-Target", "DynamoDB_20120810.Query")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "TableName": "%s",
                          "KeyConditionExpression": "pk = :pk",
                          "ExpressionAttributeValues": {":pk": {"S": "decoy-flag"}}
                        }""".formatted(DECOY_TABLE))
                .when().post("/")
                .then().statusCode(403);
    }

    @Test
    void putItemDeniedWithoutAllow() {
        given()
                .header("Authorization", playerAuth())
                .header("X-Amz-Target", "DynamoDB_20120810.PutItem")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "TableName": "%s",
                          "Item": {"pk": {"S": "new"}, "value": {"S": "x"}}
                        }""".formatted(ALLOWED_TABLE))
                .when().post("/")
                .then().statusCode(403);
    }

    private String playerAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "dynamodb");
    }
}
