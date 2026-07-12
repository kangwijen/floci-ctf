package io.github.hectorvent.floci.services.rdsdata;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.rds.model.DatabaseEngine;
import jakarta.enterprise.context.ApplicationScoped;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.util.regex.Pattern;

@ApplicationScoped
class RdsDataConnectionFactory {

    /**
     * Allowlisted database name characters for JDBC URL path segments.
     * Rejects query/fragment/path separators and control characters that would
     * enable JDBC property injection (e.g. {@code ?allowLoadLocalInfile=true}).
     */
    private static final Pattern SAFE_DATABASE_NAME = Pattern.compile("^[A-Za-z0-9_$-]+$");

    Connection open(RdsDataResourceResolver.DatabaseTarget target,
                    String username,
                    String password,
                    String database) throws SQLException {
        String url = buildUrl(target.engine(), target.host(), target.port(), database);
        Properties props = new Properties();
        props.setProperty("user", username);
        props.setProperty("password", password);
        props.setProperty("connectTimeout", connectTimeout(target.engine()));
        return DriverManager.getConnection(url, props);
    }

    static String buildUrl(DatabaseEngine engine, String host, int port, String database) {
        validateDatabaseName(database);
        return switch (engine) {
            case MYSQL, MARIADB -> "jdbc:mysql://" + host + ":" + port + "/" + database
                    + "?useSSL=false&allowPublicKeyRetrieval=true";
            case POSTGRES -> "jdbc:postgresql://" + host + ":" + port + "/" + database
                    + "?sslmode=disable";
        };
    }

    static void validateDatabaseName(String database) {
        if (database == null || !SAFE_DATABASE_NAME.matcher(database).matches()) {
            throw new AwsException("BadRequestException", "Invalid database name.", 400);
        }
    }

    private static String connectTimeout(DatabaseEngine engine) {
        // MySQL Connector/J expects milliseconds; the PostgreSQL driver expects seconds.
        return switch (engine) {
            case MYSQL, MARIADB -> "5000";
            case POSTGRES -> "5";
        };
    }
}
