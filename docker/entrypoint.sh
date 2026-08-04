#!/bin/bash
# Sequences the sandbox's supporting services, then hands off to strace.
#
# Order: DNS sinkhole -> TLS-intercepting sinkhole -> local redirect of all
# outbound 80/443 into it -> strace-wrapped invocation of the traced command.
set -eu

MITM_PORT=8080
MITMDUMP_BIN="$(command -v mitmdump)"

echo "nameserver 127.0.0.1" > /etc/resolv.conf

# mitmproxy runs as an unprivileged user (see below); it and dnsmasq both
# need to write their logs here.
chmod 1777 /scratch

# dnsmasq: every hostname the traced process looks up resolves to loopback,
# where mitmproxy is listening.
dnsmasq --conf-file=/etc/dnsmasq.conf --no-daemon &
DNSMASQ_PID=$!

# mitmproxy: upstream_cert=false + connection_strategy=lazy means it never
# needs a real upstream connection to complete the TLS handshake with the
# traced process and decrypt/log its request — important since --network
# none (set by the caller) means any upstream attempt mitmproxy itself makes
# is guaranteed to fail anyway. Runs as a dedicated user so its own outbound
# attempts can be excluded from the redirect below (otherwise they'd loop
# back into themselves).
su -s /bin/sh mitmproxy -c "
  HOME=/etc/mitmproxy '${MITMDUMP_BIN}' \
    --mode transparent \
    --listen-host 127.0.0.1 \
    --listen-port ${MITM_PORT} \
    --set confdir=/etc/mitmproxy \
    --set upstream_cert=false \
    --set connection_strategy=lazy \
    --set termlog_verbosity=warn \
    -s /opt/sentinel/mitmproxy-addon.py
" &
MITM_PID=$!

# Local-only iptables REDIRECT: catches every outbound 80/443 attempt,
# including one that skips DNS and hardcodes a real IP, and routes it into
# mitmproxy above. Self-contained within this container's own network
# namespace — no bridge network or host-side NAT involved.
iptables -t nat -A OUTPUT -m owner --uid-owner mitmproxy -j RETURN
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port "${MITM_PORT}"
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port "${MITM_PORT}"

wait_for_port() {
    local port="$1" label="$2" tries=50
    while ! (echo > "/dev/tcp/127.0.0.1/${port}") 2>/dev/null; do
        tries=$((tries - 1))
        if [ "${tries}" -le 0 ]; then
            echo "sentinel: ${label} on port ${port} never became ready" >&2
            exit 97
        fi
        sleep 0.1
    done
}

wait_for_port 53 dnsmasq &
DNSMASQ_WAIT_PID=$!
wait_for_port "${MITM_PORT}" mitmproxy &
MITM_WAIT_PID=$!
wait "${DNSMASQ_WAIT_PID}" "${MITM_WAIT_PID}"

# Deliberately not `exec`ing strace here: this script must stay alive as a
# real parent process so dnsmasq/mitmproxy above remain its children rather
# than getting reparented onto whatever becomes PID 1. If strace itself took
# over as PID 1 (via exec), it would inherit those still-running background
# processes as its own children and — since strace's wait loop doesn't
# distinguish its traced target from unrelated children — block on their
# exit too, and the container would never stop. The caller runs this image
# with `docker run --init` so a proper init (tini) is the real PID 1; tini
# stops the container based on this script's own exit, independent of
# whatever's still running underneath it.
set +e
strace -f -tt -s 256 -e trace=execve,connect,openat -o /scratch/strace.log -- "$@"
STRACE_EXIT=$?
set -e

kill "${DNSMASQ_PID}" "${MITM_PID}" 2>/dev/null || true

# dnsmasq drops root privileges after binding port 53 and writes its log as
# that unprivileged internal user; mitmproxy's log is written as the
# dedicated mitmproxy user. On a real Linux Docker daemon (bind mounts share
# host UIDs directly, unlike Docker Desktop's filesystem-sharing layer, which
# normalizes this away), the host-side reader is neither of those internal
# users and gets denied. Flatten to world-readable at the one point that
# actually crosses the container/host boundary, rather than chasing each
# writer's own umask.
chmod 644 /scratch/*.log 2>/dev/null || true

exit "${STRACE_EXIT}"
