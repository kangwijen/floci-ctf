FROM maven:3.9-eclipse-temurin-17
WORKDIR /app

COPY pom.xml .
RUN mvn dependency:go-offline -q

COPY src/ src/
RUN mvn test-compile -q

ENV FLOCI_ENDPOINT=http://floci:4566

RUN groupadd -g 1000 appuser && useradd -m -u 1000 -g appuser appuser \
    && mkdir -p /results \
    && cp -a /root/.m2 /home/appuser/.m2 \
    && chown -R appuser:appuser /app /results /home/appuser
USER appuser
ENV HOME=/home/appuser
ENTRYPOINT ["bash", "-c", "status=0; mvn test -q -Dorg.slf4j.simpleLogger.defaultLogLevel=warn || status=$?; if [ -d target/surefire-reports ]; then cp target/surefire-reports/TEST-*.xml /results/ 2>/dev/null || true; fi; exit $status"]
