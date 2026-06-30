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
 * {@code dynamodb:PutItem} scoped via {@code TableName} in the JSON request body.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DynamoDbPutItemScopedIntegrationTest {

    private static final String DYNAMODB_CONTENT_TYPE = "application/x-amz-json-1.0";
    private static final String ALLOWED_TABLE = "allowed-write-table";
    private static final String DECOY_TABLE = "decoy-write-table";

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ddb-put-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "dynamodb");

        createTable(rootAuth, ALLOWED_TABLE);
        createTable(rootAuth, DECOY_TABLE);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"dynamodb:PutItem",
               "Resource":"arn:aws:dynamodb:us-east-1:%s:table/%s"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT, ALLOWED_TABLE);
        CtfLabIamTestSupport.putUserPolicy(user, "ddb-put-one", policy);
    }

    @Test
    void putItemAllowedTable() {
        putItem(playerAuth(), ALLOWED_TABLE, "allowed-row")
                .statusCode(200);
    }

    @Test
    void putItemDecoyTableDenied() {
        putItem(playerAuth(), DECOY_TABLE, "decoy-row")
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
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

    private static io.restassured.response.ValidatableResponse putItem(String auth, String tableName, String pk) {
        return given()
                .header("Authorization", auth)
                .header("X-Amz-Target", "DynamoDB_20120810.PutItem")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "TableName": "%s",
                          "Item": {"pk": {"S": "%s"}}
                        }""".formatted(tableName, pk))
                .when().post("/")
                .then();
    }

    private String playerAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "dynamodb");
    }
}
