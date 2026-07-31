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
)


def is_benign_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in BENIGN_OPEN_PREFIXES)
