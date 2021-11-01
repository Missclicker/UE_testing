import requests
import json
import sys
from datetime import datetime
from types import SimpleNamespace


class FMCAuthError(Exception):
    pass


class FMC:
    """
        class for handling FMC authentication and general queries (FTDs, Objects)
    """

    urls = SimpleNamespace(**{
        'generate_token': '/api/fmc_platform/v1/auth/generatetoken',
        'refresh_token': '/api/fmc_config/v1/auth/refreshtoken',
        'device': '/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords',
        'ha': '/api/fmc_config/v1/domain/{domainUUID}/devicehapairs/ftddevicehapairs'
    })

    def __init__(self, fmc_ip: str, protocol: str, login: str, password: str):
        # disabling warnings & proxy
        requests.packages.urllib3.disable_warnings()
        self.session = requests.Session()
        self.session.trust_env = False
        self.ip = fmc_ip
        #   https:// + 1.1.1.1
        self.host = protocol + self.ip
        self._login = login
        self._password = password
        self._auth_token = ''
        self._refresh_token = ''
        self.headers = {'Content-Type': 'application/json'}
        self.domainUUID = ''
        self._get_token()
        self.need_refresh = True

    def _get_token(self):
        """
            gets tokens using basic auth. Runs on init or when refresh fails
        """
        auth_url = self.host + FMC.urls.generate_token
        try:
            auth_headers = self.session.post(
                auth_url, headers=self.headers, auth=requests.auth.HTTPBasicAuth(self._login, self._password),
                verify=False
            ).headers
            domains = json.loads(auth_headers.get('DOMAINS', default=None))
            self.domainUUID = domains[0]["uuid"]
            self._auth_token = auth_headers.get('X-auth-access-token', default=None)
            self._refresh_token = auth_headers.get('X-auth-refresh-token', default=None)
            if self._auth_token is None:
                print('auth_token not found. Exiting...')
                sys.exit()
        except Exception as err:
            print('Error in generating auth token --> ' + str(err))
            sys.exit()
        else:
            self.headers = {
                'Content-Type': 'application/json',
                'X-auth-access-token': self._auth_token,
                'X-auth-refresh-token': self._refresh_token
            }

    def _get_refreshed_token(self):
        """
            try to refresh auth token, call new token if fails
        """
        print('X-auth token timeout, refreshing...')
        refresh_url = self.host + FMC.urls.refresh_token
        r = self.session.post(refresh_url, headers=self.headers, verify=False)
        if r.status_code != 204:
            print('Error while refreshing API token. Generating new...')
            self._get_token()
        else:
            auth_headers = r.headers
            self._auth_token = auth_headers.get('X-auth-access-token', default=None)
            self._refresh_token = auth_headers.get('X-auth-refresh-token', default=None)
            self.headers = {
                'Content-Type': 'application/json',
                'X-auth-access-token': self._auth_token,
                'X-auth-refresh-token': self._refresh_token
            }
        print('...done! Processing query')

    def _refresh_token_decorator(func):
        """
            decorator for different GET class methods to handle Authentication
        """

        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except FMCAuthError:
                self._get_refreshed_token()
                # once the token is refreshed, we can retry the operation
                # TODO auth loop protection?
                return func(self, *args, **kwargs)

        return wrapper

    # noinspection PyArgumentList
    @_refresh_token_decorator
    def get_fws_from_fmc(self, cache_path: str = 'C:\\check_data\\ftd_checks\\'):
        """
            form, return & save json with FTD info
        """
        api_path = f'/api/fmc_config/v1/domain/{self.domainUUID}/devices/devicerecords?expanded=true&limit=1000'
        url = self.host + api_path
        r = self.session.get(url, headers=self.headers, verify=False)
        if r.status_code == 401:
            raise FMCAuthError('Auth failure')
        all_fws = {}
        for i in r.json()['items']:
            all_fws[i['name']] = {
                'id': i['id'],
                'ha': i['metadata']['isPartOfContainer'],
                'ha_id': None if not i['metadata']['isPartOfContainer'] else i['metadata']['containerDetails']['id'],
                'sw': i['sw_version'],
                'mgmt': i['hostName'],
                'health': i['healthStatus'],
                'sw_version': i['sw_version'],
                'group': None if 'deviceGroup' not in i.keys() else i['deviceGroup']['name']
            }
        date = datetime.now().date().isoformat()
        with open(f'{cache_path}fmc_on_ftd_{date}.json', 'wt') as f:
            json.dump(all_fws, f, indent=4)
        self.need_refresh = False
        return all_fws

    @_refresh_token_decorator
    def api_get_call(self, uri_string, *args, **kwargs) -> requests.models.Response:
        if 'domainUUID' in uri_string:
            uri_string = uri_string.format(
                **{'domainUUID': self.domainUUID}
            )
        url = self.host + uri_string
        r = self.session.get(url, headers=self.headers, verify=False)
        if r.status_code == 401:
            raise FMCAuthError('Auth failure')
        return r

    @_refresh_token_decorator
    def delete_from_fmc(self, uri_string, obj_id) -> requests.models.Response:
        url = self.host + uri_string.format(**{
            'domainUUID': self.domainUUID
        }) + '/' + obj_id
        r = self.session.delete(url, headers=self.headers)
        if r.status_code == 401:
            raise FMCAuthError('Auth failure')
        return r

    @_refresh_token_decorator
    def post_to_fmc(self, uri_string: str, post_data: json) -> requests.models.Response:
        if 'domainUUID' in uri_string:
            uri_string = uri_string.format(
                **{'domainUUID': self.domainUUID}
            )
        url = self.host + uri_string
        r = self.session.post(url, headers=self.headers, json=post_data)
        if r.status_code == 401:
            raise FMCAuthError('Auth failure')
        return r


if __name__ == '__main__':
    from pass_config import FMC_IP, FMC_LOGIN, PASSWORD, CACHE_PATH, FMC_PROTOCOL

    # fmc = FMC(
    #     fmc_ip=FMC_IP,
    #     protocol=FMC_PROTOCOL,
    #     login=FMC_LOGIN,
    #     password=PASSWORD,
    #     cache_path=CACHE_PATH
    # )
    # fmc.get_fws_from_fmc()
    pass
