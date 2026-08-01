# Skill Sentinel sandbox image.
#
# Runs a candidate skill under strace, with all DNS lookups sinkholed to a
# local mitmproxy instance (via dnsmasq) so HTTPS traffic decrypts for the
# report instead of showing up as a bare IP. The container is run with
# --network none by the caller (sentinel/sandbox.py) — there is no route to
# the real internet regardless of what this image sets up; a local iptables
# REDIRECT (self-contained within the container's own network namespace,
# not a bridge/NAT setup) is what gets a skill's outbound attempt — even one
# that hardcodes a real IP and skips DNS entirely — into mitmproxy so its
# full intent (host, path, body) still gets captured before mitmproxy's own
# (necessarily failing, since there is no route out) upstream connection
# attempt is made.
FROM python:3.12-slim

# Build-time proxy plumbing for environments that require it (e.g. behind a
# corporate MITM proxy). Unused/empty by default; not persisted into ENV so
# it doesn't leak into the sandboxed runtime, where it would be meaningless
# anyway since the container runs with --network none.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        strace \
        ca-certificates \
        iptables \
        dnsmasq \
        nodejs \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir mitmproxy

# Dedicated non-root user for mitmproxy: iptables excludes traffic sourced
# from this user's own outbound connections from the REDIRECT rule below,
# which is what prevents mitmproxy's own (already-doomed, since there's no
# route out) upstream connection attempts from being redirected back into
# itself and looping.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin mitmproxy

COPY dnsmasq.conf /etc/dnsmasq.conf
COPY mitmproxy-addon.py /opt/sentinel/mitmproxy-addon.py
COPY entrypoint.sh /opt/sentinel/entrypoint.sh
RUN chmod +x /opt/sentinel/entrypoint.sh

# Pre-bake mitmproxy's CA at build time (not on first run) so it can be
# trusted system-wide before the traced process ever starts, avoiding a
# generate-then-trust race at container start.
RUN mkdir -p /etc/mitmproxy && chown mitmproxy:mitmproxy /etc/mitmproxy && \
    timeout 5 su -s /bin/sh mitmproxy -c "HOME=/etc/mitmproxy $(command -v mitmdump) --set confdir=/etc/mitmproxy -q" || true; \
    test -f /etc/mitmproxy/mitmproxy-ca-cert.pem

# Trust the mitmproxy CA system-wide (covers curl, most system tools)...
RUN cp /etc/mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt && \
    update-ca-certificates
# ...and explicitly for runtimes that ship their own CA bundle instead of
# reading the OS store (Python's requests/urllib3 via certifi, Node, curl
# config, generic OpenSSL-based tools).
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV NODE_EXTRA_CA_CERTS=/etc/mitmproxy/mitmproxy-ca-cert.pem
ENV CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
RUN cat /etc/mitmproxy/mitmproxy-ca-cert.pem >> "$(python3 -c 'import certifi; print(certifi.where())')" \
    || pip install --no-cache-dir certifi \
    && cat /etc/mitmproxy/mitmproxy-ca-cert.pem >> "$(python3 -c 'import certifi; print(certifi.where())')"
RUN chown -R mitmproxy:mitmproxy /etc/mitmproxy

RUN mkdir -p /scratch /skill
WORKDIR /skill

ENTRYPOINT ["/opt/sentinel/entrypoint.sh"]
