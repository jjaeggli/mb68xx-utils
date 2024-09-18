#!/usr/bin/python

import argparse
import modem
import os


MODEM_ADDRESS = 'MODEM_ADDRESS'
MODEM_PASSWORD = 'MODEM_PASSWORD'


def print_response(response: modem.MultipleHnapsResponse):
    for ch in response.getUpstreamChannelInfo():
        print(ch)

    for ch in response.getDownstreamChannelInfo():
        print(ch)

    print(response.getConnectionInfo())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--reboot', dest='reboot', action='store_true',
                        help='Reboot the router after capture')
    parser.add_argument('-s', '--stdout', dest='stdout', action='store_true',
                        help='Print output to stdout')
    args = parser.parse_args()

    modem_address = os.environ.get(MODEM_ADDRESS, '192.168.100.1')
    modem_password = os.environ.get(MODEM_PASSWORD, '')

    m = modem.Modem(modem_address, modem_password)
    m.login()

    if args.stdout:
        response = m.get_status()
        print_response(response)

    if args.reboot:
        m.reboot()


if __name__ == "__main__":
    main()