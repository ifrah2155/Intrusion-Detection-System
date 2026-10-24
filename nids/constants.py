"""Shared vocabulary: attack labels, severities and protocol constants.

Keeping these in one module means the traffic generator, the detection engine
and the evaluation code can never silently disagree about what a label means.
"""

from __future__ import annotations

from enum import IntEnum


# --------------------------------------------------------------------------
# Ground-truth attack taxonomy
# --------------------------------------------------------------------------
BENIGN = "benign"
PORT_SCAN = "port_scan"
DOS = "dos"
BRUTE_FORCE = "brute_force"
MITM = "mitm"

ALL_LABELS = (BENIGN, PORT_SCAN, DOS, BRUTE_FORCE, MITM)
ATTACK_LABELS = (PORT_SCAN, DOS, BRUTE_FORCE, MITM)

LABEL_DESCRIPTIONS = {
    BENIGN: "Normal user / application traffic",
    PORT_SCAN: "Reconnaissance: TCP SYN / NULL / horizontal port scanning",
    DOS: "Denial of service: SYN, UDP or ICMP flooding",
    BRUTE_FORCE: "Credential brute force against SSH / RDP",
    MITM: "Man-in-the-middle via ARP cache poisoning",
}


class AttackLabel(IntEnum):
    """Numeric encoding used by the supervised classifier."""

    BENIGN = 0
    PORT_SCAN = 1
    DOS = 2
    BRUTE_FORCE = 3
    MITM = 4

    @classmethod
    def from_name(cls, name: str) -> "AttackLabel":
        return cls[{"benign": "BENIGN", "port_scan": "PORT_SCAN", "dos": "DOS",
                    "brute_force": "BRUTE_FORCE", "mitm": "MITM"}[name]]


# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------
class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Map a 0-1 confidence/severity score onto a discrete band."""
        if score >= 0.85:
            return cls.CRITICAL
        if score >= 0.65:
            return cls.HIGH
        if score >= 0.45:
            return cls.MEDIUM
        if score >= 0.25:
            return cls.LOW
        return cls.INFO


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# --------------------------------------------------------------------------
# Protocol numbers
# --------------------------------------------------------------------------
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

PROTO_NAMES = {IPPROTO_ICMP: "ICMP", IPPROTO_TCP: "TCP", IPPROTO_UDP: "UDP"}

# --------------------------------------------------------------------------
# TCP flag bitmask helpers
# --------------------------------------------------------------------------
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

FLAG_NAMES = (
    (TCP_FIN, "F"),
    (TCP_SYN, "S"),
    (TCP_RST, "R"),
    (TCP_PSH, "P"),
    (TCP_ACK, "A"),
    (TCP_URG, "U"),
)


def flags_to_str(flags: int) -> str:
    """Render a TCP flag bitmask as the familiar ``SA`` / ``PA`` shorthand."""
    out = "".join(ch for bit, ch in FLAG_NAMES if flags & bit)
    return out or "-"


# Well known service ports referenced by rules and the generator
PORT_SSH = 22
PORT_DNS = 53
PORT_HTTP = 80
PORT_HTTPS = 443
PORT_SMB = 445
PORT_MYSQL = 3306
PORT_RDP = 3389
PORT_NTP = 123
