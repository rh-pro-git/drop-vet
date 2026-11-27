# The read-only history page only. The intake needs bubblewrap with user namespaces and runs on the host.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd -r -u 10001 drop-vet
USER drop-vet
ENV DROP_VET_ROOT=/data DROP_VET_STATE_DIR=/data/.state DROP_VET_HOST=0.0.0.0 DROP_VET_PORT=8750
VOLUME ["/data"]
EXPOSE 8750
CMD ["drop-vet", "serve"]
