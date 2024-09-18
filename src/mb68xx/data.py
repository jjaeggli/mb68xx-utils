import dataclasses


@dataclasses.dataclass
class ConnectionInfo:
    uptime: int
    network_access: bool

    def as_dict(self):
        return dataclasses.asdict(self)


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

    def as_dict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass
class UpstreamChannelInfo:
    channel: int
    channel_id: int
    locked: bool
    rate: int
    pwr: float

    def as_dict(self):
        return dataclasses.asdict(self)
