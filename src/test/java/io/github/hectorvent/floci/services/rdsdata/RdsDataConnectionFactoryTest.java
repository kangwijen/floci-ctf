package io.github.hectorvent.floci.services.rdsdata;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.rds.model.DatabaseEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RdsDataConnectionFactoryTest {

    @Test
    void buildsMysqlUrl() {
        assertEquals(
                "jdbc:mysql://127.0.0.1:3306/app?useSSL=false&allowPublicKeyRetrieval=true",
                RdsDataConnectionFactory.buildUrl(DatabaseEngine.MYSQL, "127.0.0.1", 3306, "app"));
    }

    @Test
    void buildsMariadbUrlUsingMysqlDriver() {
        assertEquals(
                "jdbc:mysql://127.0.0.1:3306/app?useSSL=false&allowPublicKeyRetrieval=true",
                RdsDataConnectionFactory.buildUrl(DatabaseEngine.MARIADB, "127.0.0.1", 3306, "app"));
    }

    @Test
    void buildsPostgresUrl() {
        assertEquals(
                "jdbc:postgresql://127.0.0.1:5432/app?sslmode=disable",
                RdsDataConnectionFactory.buildUrl(DatabaseEngine.POSTGRES, "127.0.0.1", 5432, "app"));
    }

    @Test
    void buildsUrlWithAllowlistedSpecialChars() {
        assertEquals(
                "jdbc:mysql://127.0.0.1:3306/app_db-1$name?useSSL=false&allowPublicKeyRetrieval=true",
                RdsDataConnectionFactory.buildUrl(
                        DatabaseEngine.MYSQL, "127.0.0.1", 3306, "app_db-1$name"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            "app?allowLoadLocalInfile=true",
            "app#frag",
            "app;autoReconnect=true",
            "app/../other",
            "app\\other",
            "app db",
            "app\tdb",
            "app\ndb",
            "app\u0000db"
    })
    void rejectsUnsafeDatabaseNames(String database) {
        AwsException error = assertThrows(AwsException.class,
                () -> RdsDataConnectionFactory.buildUrl(
                        DatabaseEngine.MYSQL, "127.0.0.1", 3306, database));

        assertEquals("BadRequestException", error.getErrorCode());
        assertEquals(400, error.getHttpStatus());
        assertEquals("Invalid database name.", error.getMessage());
    }
}
