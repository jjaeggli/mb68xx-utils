import hmac
import time
import requests
import json

_DIGEST_MD5 = 'MD5'
_ACTION_FORMAT = 'http://purenetworks.com/HNAP1/{}'


class Modem:
    """Class for interacting with a HNAP-based API on a MB68xx cable modem."""

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

    def _login_real(self, passkey) -> requests.Response:
        payload = {'Login': {'Action': 'login',
                             'Captcha': '',
                             'LoginPassword': str(passkey),
                             'PrivateLogin': 'LoginPassword',
                             'Username': 'admin'}}
        return self._soap_action('Login', payload)

    def login(self):
        """Complete the challenge / response authentication workflow."""
        r = self._login_request()
        json_response = json.loads(r.text)
        lrdata = json_response['LoginResponse']
        pubkey = lrdata['PublicKey']
        challenge = lrdata['Challenge']
        privkey, passkey = self._generate_keys(challenge.encode(),
                                              pubkey.encode())
        self.cookie_id = lrdata['Cookie']
        self.privatekey = privkey
        return self._login_real(passkey)

    def get_status(self):
        """Request metrics from the modem."""
        payload = {'GetMultipleHNAPs': {'GetMotoStatusStartupSequence': '',
                                        'GetMotoStatusConnectionInfo': '',
                                        'GetMotoStatusDownstreamChannelInfo': '',
                                        'GetMotoStatusUpstreamChannelInfo': '',
                                        'GetMotoLagStatus': ''}}
        return self._soap_action('GetMultipleHNAPs', payload)

    def reboot(self) -> requests.Response:
        """Perform a modem reboot."""
        payload = {'SetStatusSecuritySettings': {'MotoStatusSecurityAction': '1',
                                                 'MotoStatusSecXXX': 'XXX'}}
        return self._soap_action('SetStatusSecuritySettings', payload)
