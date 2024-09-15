import dataclasses


@dataclasses.dataclass
class ConnectionInfo:
    uptime: int
    network_access: bool


@dataclasses.dataclass
class DownstreamChannelInfo:
    locked: bool
    pwr: float
    snr: float
    corrected: int
    uncorrected: int


@dataclasses.dataclass
class UpstreamChannelInfo:
    locked: bool
    rate: int
    pwr: float