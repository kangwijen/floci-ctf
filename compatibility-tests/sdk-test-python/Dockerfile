FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY conftest.py pytest.ini ./
COPY tests/ tests/

ENV FLOCI_ENDPOINT=http://floci:4566

RUN groupadd -g 1000 appuser && useradd -m -u 1000 -g appuser appuser \
    && mkdir -p /results \
    && chown -R appuser:appuser /app /results
USER appuser
ENTRYPOINT ["pytest", "tests/", "-v", "--junit-xml=/results/junit.xml"]
