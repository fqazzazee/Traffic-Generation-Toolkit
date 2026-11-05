"""TGT — Traffic Generation Toolkit.

Craft OT/ICS and IT test traffic and put it on a virtual interface so a
monitoring tool (Zeek, Suricata, Security Onion, Claroty CTD, …) can capture it.
Pure Python standard library — no scapy, no external packages.
"""
# The one place the version lives: pyproject.toml reads it (dynamic version)
# and `tgt --version` prints it.
__version__ = "1.5.0"
