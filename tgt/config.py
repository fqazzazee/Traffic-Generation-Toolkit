"""Run configuration shared by the CLI and the TUI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .packet import Endpoints


@dataclass
class RunConfig:
    profiles: List[str] = field(default_factory=lambda: ["modbus"])
    env: Optional[str] = None            # modeled environment; overrides profiles
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
        what = f"env={self.env}" if self.env else f"profiles={','.join(self.profiles)}"
        return (f"{what} iface={target} "
                f"rate={self.rate}pps {stop} loop={self.loop}")
