import dataclasses


@dataclasses.dataclass
class ConnectionInfo:
    uptime: int
    network_access: bool


@dataclasses.dataclass
class DownstreamChannelInfo:
    channel: int
    channel_id: int
    freq: float
    locked: bool
    snr: float
    pwr: float
    corrected: int
    uncorrected: int


@dataclasses.dataclass
class UpstreamChannelInfo:
    channel: int
    channel_id: int
    locked: bool
    rate: int
    pwr: float
