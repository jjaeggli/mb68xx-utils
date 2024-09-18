#!/usr/bin/python
"""Module provides interactive actions for MB68xx modems."""

import actions_influxdb
import argparse
import modem
import os


MODEM_ADDRESS = 'MODEM_ADDRESS'
MODEM_PASSWORD = 'MODEM_PASSWORD'

INFLUXDB_URL = 'INFLUXDB_URL'
INFLUXDB_ORG = 'INFLUXDB_ORG'
INFLUXDB_TOKEN = 'INFLUXDB_TOKEN'
INFLUXDB_BUCKET = 'INFLUXDB_BUCKET'


def print_response(response: modem.MultipleHnapsResponse):
    """Prints modem status and connectivity to stdout."""
    for ch in response.getUpstreamChannelInfo():
        print(ch)

    for ch in response.getDownstreamChannelInfo():
        print(ch)

    print(response.getConnectionInfo())


def record_influxdb(response: modem.MultipleHnapsResponse):
    influxdb_url = os.environ.get(INFLUXDB_URL, 'http://influxdb:8086/')
    influxdb_org = os.environ.get(INFLUXDB_ORG)
    influxdb_token = os.environ.get(INFLUXDB_TOKEN)
    influxdb_bucket = os.environ.get(INFLUXDB_BUCKET, 'mb68xx')

    assert influxdb_org is not None, 'Environment variable {} must be defined.'.format(
        INFLUXDB_ORG)
    assert influxdb_token is not None, 'Environment variable {} must be defined.'.format(
        INFLUXDB_TOKEN)

    influxdb_action = actions_influxdb.InfluxDbAction(
        influxdb_url, influxdb_org, influxdb_token, influxdb_bucket)
    influxdb_action.write_response(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--reboot', dest='reboot', action='store_true',
                        help='Reboot the router after capture')
    parser.add_argument('-s', '--stdout', dest='stdout', action='store_true',
                        help='Print output to stdout')
    parser.add_argument('-i', '--influxdb', dest='influxdb', action='store_true',
                        help='Record response to influxdb')
    args = parser.parse_args()

    modem_address = os.environ.get(MODEM_ADDRESS, '192.168.100.1')
    modem_password = os.environ.get(MODEM_PASSWORD, '')

    m = modem.Modem(modem_address, modem_password)
    m.login()

    if args.stdout or args.influxdb:
        response = m.get_status()

        if args.stdout:
            print_response(response)

        if args.influxdb:
            record_influxdb(response)

    if args.reboot:
        m.reboot()


if __name__ == "__main__":
    main()
