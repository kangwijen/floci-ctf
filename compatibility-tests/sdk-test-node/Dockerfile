FROM node:22-slim
WORKDIR /app

COPY package*.json ./
RUN npm install --no-fund --no-audit

COPY tsconfig.json vitest.config.ts ./
COPY tests/ tests/

ENV FLOCI_ENDPOINT=http://floci:4566
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
ENV TEST_RESULTS_DIR=/results

RUN groupadd -g 1000 appuser && useradd -m -u 1000 -g appuser appuser \
    && mkdir -p /results \
    && chown -R appuser:appuser /app /results
USER appuser
ENTRYPOINT ["npm", "test"]
