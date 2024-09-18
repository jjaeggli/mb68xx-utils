"""Library for interacting with Motorola MB68xx series cable modems."""

import hmac
import requests
import time

from data import ConnectionInfo, DownstreamChannelInfo, UpstreamChannelInfo
from typing import Iterator


_DIGEST_MD5 = 'MD5'
_ACTION_FORMAT = 'http://purenetworks.com/HNAP1/{}'


class ModemResponseError(Exception):
    """An exception occurring when the modem returns an unexpected response."""

    def __init__(self, msg: str, response: requests.Response):
        super().__init__(msg)
        self.response = response

    def __str__(self):
        return "{msg} - status: {code}".format(
            msg=super().__str__(),
            code=self.response.status_code
        )


class MultipleHnapsResponse():
    """Class for parsing a JSON response from a Motorola MB68xx series modem HNAP API."""

    PARENT_KEY = 'GetMultipleHNAPsResponse'
    STARTUP_SEQUENCE = 'GetMotoStatusStartupSequenceResponse'
    CONNECTION_INFO = 'GetMotoStatusConnectionInfoResponse'
    DOWNSTREAM_CHANNEL_INFO = 'GetMotoStatusDownstreamChannelInfoResponse'
    UPSTREAM_CHANNEL_INFO = 'GetMotoStatusUpstreamChannelInfoResponse'
    MOTO_LAG_STATUS = 'GetMotoLagStatusResponse'
    MULTIPLE_HNAPS = 'GetMultipleHNAPsResult'

    # Keys indexed in order of MotoConnDownstreamChannel / MotoConnUpstreamChannel response.
    DOWNSTREAM_KEYS = ['channel', 'locked', 'modulation',
                       'channel_id', 'freq', 'snr', 'pwr', 'corrected', 'uncorrected']
    UPSTREAM_KEYS = ['channel', 'locked', 'type', 'channel_id', 'rate', 'freq', 'pwr']

    def __init__(self, json_response):
        self.response = json_response[self.PARENT_KEY]

    def getConnectionInfo(self) -> ConnectionInfo:
        # {'MotoConnSystemUpTime': '0 days 00h:55m:13s',
        #  'MotoConnNetworkAccess': 'Allowed',
        #  'GetMotoStatusConnectionInfoResult': 'OK'}
        info = self.response[self.CONNECTION_INFO]
        days, hms = info['MotoConnSystemUpTime'].split(' days ')
        parsed = time.strptime(hms, '%Hh:%Mm:%Ss')
        uptime = (int(days) * 24 + parsed.tm_hour) * 3600 + parsed.tm_min * 60 + parsed.tm_sec

        return ConnectionInfo(
            uptime=uptime,
            network_access=info['MotoConnNetworkAccess'].lower() == 'allowed'
        )

    def getDownstreamChannelInfo(self) -> Iterator[DownstreamChannelInfo]:
        if self.DOWNSTREAM_CHANNEL_INFO not in self.response:
            return iter([])

        channels = self.response[self.DOWNSTREAM_CHANNEL_INFO]['MotoConnDownstreamChannel']

        # channels delimited by '|+|' and fields delimited by '^' ie:
        # 1^Locked^QAM256^17^519.0^ 1.5^42.7^0^0^|+|2^Locked^QAM256^13^489.0^ 1.8^42.8^0^0^
        for ch in channels.split('|+|'):
            channel = dict(zip(self.DOWNSTREAM_KEYS, ch.strip('^').split('^')))

            yield DownstreamChannelInfo(
                channel=int(channel['channel']),
                channel_id=int(channel['channel_id']),
                freq=float(channel['freq']),
                locked=(channel['locked'].lower() == 'locked'),
                pwr=float(channel['pwr']),
                snr=float(channel['snr']),
                corrected=int(channel['corrected']),
                uncorrected=int(channel['uncorrected']),
            )

    def getUpstreamChannelInfo(self) -> Iterator[UpstreamChannelInfo]:
        if self.UPSTREAM_CHANNEL_INFO not in self.response:
            return iter([])

        channels = self.response[self.UPSTREAM_CHANNEL_INFO]['MotoConnUpstreamChannel']

        for ch in channels.split('|+|'):
            channel = dict(zip(self.UPSTREAM_KEYS, ch.strip('^').split('^')))

            yield UpstreamChannelInfo(
                channel=int(channel['channel']),
                channel_id=int(channel['channel_id']),
                locked=(channel['locked'].lower() == 'locked'),
                rate=int(channel['rate']),
                pwr=float(channel['pwr']),
            )


class Modem:
    """Class for interacting with a Motorola MB68xx series cable modem HNAP API."""

    def __init__(self, hostname: str, password: str, verify=False):
        """Initialize the modem.

        Args:
            hostname: hostname or IP address of the device.
            password: admin password of the device.
            verify: should the SSL certificate be verified. Default: False
        """
        self.hostname = hostname
        self.password = password

        self.session = requests.Session()
        self.session.verify = verify
        self.privatekey = None
        self.cookie_id = None

    def _get_hnap_uri(self) -> str:
        return 'https://{}/HNAP1/'.format(self.hostname)

    def _generate_keys(self, challenge: str, pubkey: str):
        privatekey = hmac.new(pubkey + self.password.encode(), challenge,
                              _DIGEST_MD5).hexdigest().upper()
        passkey = hmac.new(privatekey.encode(), challenge,
                           _DIGEST_MD5).hexdigest().upper()
        return (privatekey, passkey)

    def _generate_hnap_auth(self, soapaction) -> str:
        curtime = str(int(time.time() * 1000))
        auth_key = curtime + str(soapaction)
        auth = hmac.new(self.privatekey.encode(), auth_key.encode(), 'MD5')
        return auth.hexdigest().upper() + ' ' + curtime

    def _soap_action(self, action, payload) -> requests.Response:
        soapaction = _ACTION_FORMAT.format(action)
        auth = self._generate_hnap_auth(soapaction)
        headers = {'HNAP_AUTH': auth,
                   'content-type': 'application/json',
                   'soapaction': soapaction}
        cookies = {'uid': str(self.cookie_id),
                   'PrivateKey': str(self.privatekey)}
        return self.session.post(
            self._get_hnap_uri(),
            headers=headers, cookies=cookies, json=payload, timeout=10.0)

    def _login_request(self) -> requests.Response:
        soapaction = _ACTION_FORMAT.format('Login')
        headers = {
            'content-type': 'application/json',
            'soapaction': soapaction}
        payload = {'Login': {'Action': 'request', 'Username': 'admin',
                             'LoginPassword': '', 'Captcha': '', 'PrivateLogin': 'LoginPassword'}}

        return self.session.post(self._get_hnap_uri(), headers=headers, json=payload, stream=True)

    def _login_real(self, passkey):
        payload = {'Login': {'Action': 'login',
                             'Captcha': '',
                             'LoginPassword': str(passkey),
                             'PrivateLogin': 'LoginPassword',
                             'Username': 'admin'}}
        response = self._soap_action('Login', payload)
        _check_valid_response(response)
        # possibly assert the result json_response['LoginResponse']['LoginResult'] == 'OK'
        # but this will have an 'OK' response even when using a non-admin password.

    def login(self):
        """Complete the challenge / response authentication workflow."""
        response = self._login_request()
        json_response = _check_valid_response(response)
        login_response = json_response['LoginResponse']

        # Request may fail here, possibly due to multiple invalid login requests.
        if 'PublicKey' not in login_response:
            raise ModemResponseError('PublicKey not present in response. ' '') 
        pubkey = login_response['PublicKey']
        challenge = login_response['Challenge']
        privkey, passkey = self._generate_keys(challenge.encode(),
                                               pubkey.encode())
        self.cookie_id = login_response['Cookie']
        self.privatekey = privkey
        self._login_real(passkey)

    def get_status(self) -> MultipleHnapsResponse:
        """Request metrics from the modem."""
        payload = {'GetMultipleHNAPs': {'GetMotoStatusStartupSequence': '',
                                        'GetMotoStatusConnectionInfo': '',
                                        'GetMotoStatusDownstreamChannelInfo': '',
                                        'GetMotoStatusUpstreamChannelInfo': '',
                                        'GetMotoLagStatus': ''}}
        response = self._soap_action('GetMultipleHNAPs', payload)
        return MultipleHnapsResponse(_check_valid_response(response))

    def reboot(self) -> requests.Response:
        """Perform a modem reboot."""
        payload = {'SetStatusSecuritySettings': {'MotoStatusSecurityAction': '1',
                                                 'MotoStatusSecXXX': 'XXX'}}
        return self._soap_action('SetStatusSecuritySettings', payload)


def _check_valid_response(response: requests.Response):
    if (response.status_code == 200):
        try:
            return response.json()
        except requests.exceptions.JSONDecodeError as e:
            raise ModemResponseError('Could not parse JSON response', response) from e

    raise ModemResponseError('Unexpected response code', response)
