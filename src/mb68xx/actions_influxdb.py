"""Module provides actions for recording an HNAP response directly to InfluxDB."""

import data
import itertools
import influxdb_client

from influxdb_client.client.write_api import SYNCHRONOUS
from influxdb_client.domain.write_precision import WritePrecision
from modem import MultipleHnapsResponse


class InfluxDbAction():
    """Action which records a MultipleHnapsResponse to InfluxDb."""

    def __init__(self, url: str, org: str, token: str, bucket: str):
        """Initializes the InfluxDbAction class."""
        self.client = influxdb_client.InfluxDBClient(
            url=url,
            token=token,
            org=org
        )
        self._org = org
        self._bucket = bucket
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)

    def write_response(self, response: MultipleHnapsResponse):
        self.write_api.write(self._bucket, self._org, get_points(response),
                             write_precision=WritePrecision.S)


def get_points(response: MultipleHnapsResponse):
    """Transforms a MultipleHnapsResponse into influxdb points."""
    return itertools.chain(
        map(to_downstream_point, response.getDownstreamChannelInfo()),
        map(to_upstream_point, response.getUpstreamChannelInfo()),
        [to_connection_point(response.getConnectionInfo())])


def to_connection_point(connection: data.ConnectionInfo):
    return influxdb_client.Point.from_dict(
        connection.as_dict(),
        record_measurement_name='connection',
        record_field_keys=['uptime', 'network_access'],
        field_types={'uptime': 'uint', 'network_access': 'uint'}
    )


def to_downstream_point(channel: data.DownstreamChannelInfo):
    return influxdb_client.Point.from_dict(
        channel.as_dict(),
        record_measurement_name='downstream',
        record_tag_keys=['channel', 'channel_id'],
        record_field_keys=['locked', 'pwr', 'snr', 'corrected', 'uncorrected'],
        field_types={'locked': 'uint', 'corrected': 'uint', 'uncorrected': 'uint'})


def to_upstream_point(channel: data.UpstreamChannelInfo):
    return influxdb_client.Point.from_dict(
        channel.as_dict(),
        record_measurement_name='upstream',
        record_tag_keys=['channel', 'channel_id'],
        record_field_keys=['locked', 'rate', 'pwr'],
        field_types={'rate': 'uint'})
