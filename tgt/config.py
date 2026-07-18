"""Run configuration shared by the CLI and the TUI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .packet import Endpoints


@dataclass
class RunConfig:
    profiles: List[str] = field(default_factory=lambda: ["modbus"])
    env: Optional[str] = None            # modeled environment; overrides profiles
    incident: Optional[str] = None       # famous-incident scenario; overrides profiles
    sprinkle: List[str] = field(default_factory=list)  # incidents mixed into the base
    sprinkle_messages: int = 2           # exchanges per sprinkled incident (keeps it a minority)
    sprinkle_ratio: float = 0.0          # target malware fraction (0 = one natural cycle)
    sprinkle_random: bool = False        # pick random variant(s) + jittered placement each cycle
    replay_path: Optional[str] = None    # replay this pcap instead of generating
    replay_realtime: bool = False        # honor original pcap inter-packet timing
    iface: Optional[str] = None          # send target; None => pcap-only
    pcap_path: Optional[str] = None      # write frames here too/instead
    rate: float = 20.0                   # packets per second (0 = as fast as possible)
    count: int = 0                       # total frames to send; 0 = use duration
    duration: float = 0.0                # seconds; 0 with count=0 => run until stopped
    messages: int = 5                    # protocol exchanges per built flow cycle
    loop: bool = True                    # rebuild + resend flows continuously
    endpoints: Endpoints = field(default_factory=Endpoints)

    def summary(self) -> str:
        target = self.iface or "(pcap only)"
        stop = (f"count={self.count}" if self.count else
                f"duration={self.duration}s" if self.duration else "until stopped")
        if self.replay_path:
            what = f"replay={self.replay_path}"
        elif self.incident:
            what = f"incident={self.incident}"
        elif self.env:
            what = f"env={self.env}"
        else:
            what = f"profiles={','.join(self.profiles)}"
        if self.sprinkle or self.sprinkle_random:
            variants = "random" if self.sprinkle_random else ",".join(self.sprinkle)
            ratio = f"@{self.sprinkle_ratio:.0%}" if self.sprinkle_ratio else ""
            what += f" +malware[{variants}{ratio}]"
        return (f"{what} iface={target} "
                f"rate={self.rate}pps {stop} loop={self.loop}")
