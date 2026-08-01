"""Path prefixes treated as benign for openat() findings — extend as false positives surface."""

BENIGN_OPEN_PREFIXES = (
    "/usr/",
    "/lib/",
    "/lib64/",
    "/etc/ld.so",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/ssl/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/tmp/",
    "/scratch/",
    "/skill/",
    "/root/.cache/",
    "/usr/local/lib/python",
    "/usr/lib/python",
    # glibc NSS/resolver files opened by essentially any program that does a
    # hostname lookup, DNS resolution, or user/group lookup (getaddrinfo(),
    # id, etc.) — flagging these as notable would light up "HIGH" on nearly
    # every skill that makes a single network call, drowning real findings.
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/host.conf",
    "/etc/resolv.conf",
    "/etc/gai.conf",
    "/etc/protocols",
    "/etc/services",
    # The sandbox's own mitmproxy CA — Node is deliberately pointed at this via
    # NODE_EXTRA_CA_CERTS (see docker/Dockerfile) so TLS interception works.
    # Reading it is our own infrastructure, not the skill doing anything notable.
    "/etc/mitmproxy/",
)


def is_benign_path(path: str) -> bool:
    # path == prefix.rstrip("/"): opening a directory itself (e.g. os.walk/glob/
    # iterdir on the skill's own root) hits openat() with the bare path "/skill",
    # no trailing slash — found flagging real skills HIGH during the launch scan
    # for listing their own directory, since "/skill" doesn't startswith("/skill/").
    # Applies to every "/"-suffixed prefix here, not just "/skill/", since the same
    # bare-directory-open shape applies to /tmp/, /scratch/, /etc/ssl/, etc.
    return any(
        path == prefix.rstrip("/") or path.startswith(prefix) for prefix in BENIGN_OPEN_PREFIXES
    )
