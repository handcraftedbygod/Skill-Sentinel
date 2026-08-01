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
    # Legacy AIX-style NSS ordering config files that glibc/Node's resolver
    # probes (always together, always ENOENT on Linux) as part of standard
    # getaddrinfo() — found on every Node script that makes a network call,
    # across unrelated skills/authors, during the launch scan.
    "/etc/netsvc.conf",
    "/etc/svc.conf",
    # The sandbox's own mitmproxy CA — Node is deliberately pointed at this via
    # NODE_EXTRA_CA_CERTS (see docker/Dockerfile) so TLS interception works.
    # Reading it is our own infrastructure, not the skill doing anything notable.
    "/etc/mitmproxy/",
    # Debian package-manager state, read-only and not attacker-controlled — found
    # opened by a standard CI utility (free_disk_space.sh, common in GitHub
    # Actions workflows to reclaim runner disk space) during the launch scan.
    "/var/lib/dpkg/",
    # Standard OS/distro-family detection files — read by essentially any
    # install.sh picking a package manager. Found recurring independently across
    # 2 repos (MobiusQuant/OpenMobius-skill, alanl1234/xiaohongshu-matrices-cli)
    # during the launch scan; siblings included preemptively for the same reason.
    "/etc/os-release",
    "/etc/debian_version",
    "/etc/lsb-release",
    "/etc/redhat-release",
    "/etc/alpine-release",
    # The Python `cryptography` package bundles its own OpenSSL and reads this
    # config path on import — a standard pip-wheel artifact for a very common
    # dependency (pulled in by requests/urllib3/paramiko/etc.), not skill-authored.
    "/opt/pyca/cryptography/",
    # curl's own standard config-file lookup, checked on every invocation
    # regardless of target — not something the skill's request logic does.
    "/root/.curlrc",
    "/root/.config/curlrc",
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
