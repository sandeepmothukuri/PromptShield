FROM python:3.11-slim

# Run as an unprivileged user. The service binds a port above 1024 and writes
# only to the audit-log directory, neither of which needs root.
RUN groupadd --system --gid 10001 promptshield \
    && useradd --system --uid 10001 --gid promptshield --no-create-home promptshield

WORKDIR /app

# Install dependencies first so the layer is cached across source changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=promptshield:promptshield . .

# The audit-log directory is a mounted volume in docker-compose; creating it
# here keeps `docker run` working standalone. Ownership matters because the
# container does not run as root.
RUN mkdir -p /var/log/promptshield \
    && chown -R promptshield:promptshield /var/log/promptshield

USER promptshield

EXPOSE 8080

# Compose also declares a healthcheck; this one makes `docker run` behave the
# same way and lets other services use `condition: service_healthy`.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).status==200 else 1)"

# The proxy reads X-Forwarded-For itself (proxy.py::_context), so source_ip is
# correct without this flag. --proxy-headers additionally makes uvicorn populate
# request.client.host from the header, which keeps the fallback path consistent
# when no XFF header is present.
#
# Trust caveat: the proxy trusts X-Forwarded-For unconditionally, so a client
# that can reach :8080 directly can set source_ip to anything. Put an ingress in
# front that overwrites the header, or do not expose 8080 outside the compose
# network.
CMD ["uvicorn", "proxy:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
