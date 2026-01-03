import json
import logging
import re
import time
from collections import defaultdict

import requests

from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

__version__ = __VERSION__ = '1.1.0'


class DesecAPIException(ProviderException):
    pass


class DesecProviderException(ProviderException):
    pass


class DesecAPIMethodNotImlemented(DesecAPIException):
    pass


class DesecAPIBadRequest(DesecAPIException):
    def __init__(self):
        super(DesecAPIBadRequest, self).__init__('Bad request')


class DesecAPIUnauthorized(DesecAPIException):
    def __init__(self):
        super(DesecAPIUnauthorized, self).__init__('Unauthorized')


class DesecAPIForbidden(DesecAPIException):
    def __init__(self):
        super(DesecAPIForbidden, self).__init__('Forbidden')


class DesecAPINotFound(DesecAPIException):
    def __init__(self):
        super(DesecAPINotFound, self).__init__('Not found')


class DesecAPINotFoundFromAPI(DesecAPINotFound):
    pass


class DesecAPIMaxRetriesExceeded(DesecAPIException):
    pass


class DesecAPIMaxSleepExceeded(DesecAPIException):
    pass


class DesecProviderChangeTypeNotImplemented(DesecProviderException):
    pass


class DesecAPI:
    API_BASE_URL = 'https://desec.io/api'
    API_DOMAINS_URL = f'{API_BASE_URL}/v1/domains'

    DEFAULT_RETRIES = 5
    DEFAULT_TIMEOUT = 30
    DEFAULT_INIT_BACKOFF = 2
    DEFAULT_MAX_SLEEP = 600

    def __init__(
        self,
        token,
        retries=DEFAULT_RETRIES,
        timeout=DEFAULT_TIMEOUT,
        backoff=DEFAULT_INIT_BACKOFF,
        max_sleep=DEFAULT_MAX_SLEEP,
    ):
        self.token = token
        self.retries = retries
        self.timeout = timeout
        self.backoff = backoff
        self.max_sleep = max_sleep

        self.log = logging.getLogger('DesecAPI')

        return

    def _send_request(
        self,
        url,
        method,
        headers=None,
        data=None,
        retries=None,
        timeout=None,
        backoff=None,
        max_sleep=None,
        returncode=200,
    ):
        if retries is None:
            retries = self.retries
        if timeout is None:
            timeout = self.timeout
        if backoff is None:
            backoff = self.backoff
        if max_sleep is None:
            max_sleep = self.max_sleep
        if headers is None:
            headers = dict()

        r = None
        try:
            match method.lower():
                case 'get':
                    self.log.debug('sending get-request to api')
                    r = requests.get(url, headers=headers, timeout=timeout)
                case 'post':
                    self.log.debug('sending post-request to api')
                    r = requests.post(
                        url, headers=headers, timeout=timeout, data=data
                    )
                case 'patch':
                    self.log.debug('sending patch-request to api')
                    r = requests.patch(
                        url, headers=headers, timeout=timeout, data=data
                    )
                case _:
                    raise DesecAPIMethodNotImlemented('not implemented method')
        except (
            requests.RequestException,
            requests.ConnectionError,
            requests.HTTPError,
            requests.ConnectTimeout,
            requests.ReadTimeout,
            requests.Timeout,
        ) as exception:
            self.log.warning(f'Request failed with exception: {exception}')

        if r is not None and r.status_code != returncode:
            self.log.warning(
                f"API-Response: status code: {r.status_code} (expected {returncode}), content: {r.content.decode('UTF-8')}"
            )

            # No retrying will fix these http error
            if r.status_code == 400:
                raise DesecAPIBadRequest()
            if r.status_code == 401:
                raise DesecAPIUnauthorized()
            elif r.status_code == 403:
                raise DesecAPIForbidden()
            elif r.status_code == 404:
                try:
                    if r.json() == {"detail": "Not found."}:
                        raise DesecAPINotFoundFromAPI()
                except requests.exceptions.JSONDecodeError:
                    pass

                raise DesecAPINotFound()

        if r is None or r.status_code != returncode:
            if retries > 0:
                sleep_time = min(backoff, max_sleep)

                try:
                    sleep_time = int(
                        re.fullmatch(
                            r'Request was throttled. Expected available in (\d+) seconds?.',
                            r.json()['detail'],
                        ).group(1)
                    )

                    self.log.warning('Extracted wait time from API response')

                    if sleep_time > max_sleep:
                        raise DesecAPIMaxSleepExceeded(
                            f'API will still not be available once max_sleep (of {max_sleep} seconds) runs out'
                        )
                except (
                    ValueError,
                    AttributeError,
                    IndexError,
                    KeyError,
                    requests.exceptions.JSONDecodeError,
                ):
                    pass

                self.log.warning(f'retry in {sleep_time} sec')
                time.sleep(sleep_time)
                r = self._send_request(
                    url=url,
                    method=method,
                    headers=headers,
                    data=data,
                    retries=retries - 1,
                    timeout=timeout,
                    backoff=backoff * 2,
                    max_sleep=max_sleep,
                    returncode=returncode,
                )
            else:
                raise DesecAPIMaxRetriesExceeded('too many API-retries')

        return r

    # https://desec.readthedocs.io/en/latest/dns/domains.html#listing-domains
    def get_domains(self):
        return_json = []
        url = f'{DesecAPI.API_DOMAINS_URL}/?cursor='
        while url != '':
            response = self._send_request(
                url,
                method='get',
                headers={'Authorization': f'Token {self.token}'},
            )
            return_json = return_json + response.json()

            if 'next' in response.links:
                url = response.links['next']['url']
            else:
                url = ''

        return return_json

    # https://desec.readthedocs.io/en/latest/dns/domains.html#creating-a-domain
    def create_domain(self, domain):
        url = f'{DesecAPI.API_DOMAINS_URL}/'
        data = {"name": domain}
        return self._send_request(
            url,
            method='post',
            headers={
                'Authorization': f'Token {self.token}',
                'Content-Type': 'application/json',
            },
            data=json.dumps(data),
            returncode=201,
        ).json()

    # https://desec.readthedocs.io/en/latest/dns/rrsets.html#retrieving-all-rrsets-in-a-zone
    def get_rrset(self, domainName):
        return_json = []
        url = f'{DesecAPI.API_DOMAINS_URL}/{domainName}/rrsets/?cursor='
        while url != '':
            response = self._send_request(
                url,
                method='get',
                headers={'Authorization': f'Token {self.token}'},
            )
            return_json = return_json + response.json()

            if 'next' in response.links:
                url = response.links['next']['url']
            else:
                url = ''

        return return_json

    # https://desec.readthedocs.io/en/latest/dns/rrsets.html#modifying-an-rrset
    def update_rrset(self, domainName, rrset: list):
        self._send_request(
            f'{DesecAPI.API_DOMAINS_URL}/{domainName}/rrsets/',
            method='patch',
            headers={
                'Authorization': f'Token {self.token}',
                'Content-Type': 'application/json',
            },
            data=json.dumps(rrset),
        )


class DesecProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_ROOT_NS = True
    SUPPORTS = {
        'A',
        'AAAA',
        'CAA',
        'CNAME',
        'DS',
        'HTTPS',
        'MX',
        'NS',
        'PTR',
        'SRV',
        'TLSA',
        'TXT',
    }

    def __init__(
        self,
        id,
        token,
        retries=DesecAPI.DEFAULT_RETRIES,
        timeout=DesecAPI.DEFAULT_TIMEOUT,
        backoff=DesecAPI.DEFAULT_INIT_BACKOFF,
        max_sleep=DesecAPI.DEFAULT_MAX_SLEEP,
        *args,
        **kwargs,
    ):
        self.log = logging.getLogger(f'desecProvider[{id}]')
        self.log.debug('__init__: id=%s', id)
        self.desec_api = DesecAPI(token, retries, timeout, backoff, max_sleep)

        super().__init__(id)

    def list_zones(self):
        return [
            domain_field["name"]
            for domain_field in self.desec_api.get_domains()
        ]

    def zone_records(self, zone_name):
        # Fetch records from Desec-API that already exist
        records = []

        try:
            rrset = self.desec_api.get_rrset(zone_name.name.rstrip('.'))
        except DesecAPINotFoundFromAPI:
            return []

        for record in rrset:
            for data in record['records']:
                records.append(
                    {
                        'type': record['type'],
                        'name': record['subname'],
                        'ttl': record['ttl'],
                        'data': data,
                    }
                )

        return records

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        # fetch data from API and save to values
        values = defaultdict(lambda: defaultdict(list))
        for record in self.zone_records(zone):
            _type = record['type']
            if _type not in self.SUPPORTS:
                continue
            values[record['name']][record['type']].append(record)

        # add data from values to zone.records (octodns)
        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                data = getattr(self, f'_data_for_{_type}')(_type, records)
                record = Record.new(
                    zone, name, data, source=self, lenient=lenient
                )
                zone.add_record(record, lenient=lenient)

        exists = len(zone.records) > 0
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _apply(self, plan):
        update = []

        for change in plan.changes:
            match change.data['type']:
                case 'delete':
                    update.append(
                        {
                            "subname": change.existing.decoded_name,
                            "type": change.existing.rrs[2],
                            "ttl": '3600',  # fixed ttl - else if your ttl is 60 for dyndns-records you can not dedlete them
                            "records": [],
                        }
                    )
                case 'create':
                    update.append(
                        {
                            "subname": change.new.decoded_name,
                            "type": change.new.rrs[2],
                            "ttl": change.new.rrs[1],
                            "records": change.new.rrs[3],
                        }
                    )
                case 'update':
                    update.append(
                        {
                            "subname": change.new.decoded_name,
                            "type": change.new.rrs[2],
                            "ttl": change.new.rrs[1],
                            "records": change.new.rrs[3],
                        }
                    )
                case _:
                    raise DesecProviderChangeTypeNotImplemented(
                        'not implemented type'
                    )

        if not plan.exists:
            r = self.desec_api.create_domain(plan.desired.name.rstrip('.'))

            self.log.warning("*" * 10)
            self.log.warning(
                f"Created domain {plan.desired.name.rstrip('.')}, make sure to setup DNSSEC! (login at deSEC for details)"
            )
            self.log.warning(f'DNSKEY: {r["keys"][0]["dnskey"]}')
            for ds in r["keys"][0]["ds"]:
                self.log.warning(f"DS: {ds}")
            self.log.warning("NS: ns1.desec.io.")
            self.log.warning("NS: ns2.desec.org.")
            self.log.warning(
                f"then check with https://dnssec-analyzer.verisignlabs.com/{plan.desired.name.rstrip('.')}"
            )
            self.log.warning("*" * 10)

        self.desec_api.update_rrset(
            plan.desired.decoded_name.rstrip('.'), update
        )

    def _data_for_multiple(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': [record['data'] for record in records],
        }

    def _data_for_single(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'value': records[0]['data'],
        }

    def _data_for_TXT(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            # escape semicolons
            'values': [
                record['data'].replace(';', '\\;') for record in records
            ],
        }

    def _data_for_MX(self, _type, records):
        values = []
        for record in records:
            values.append(
                {
                    'preference': record['data'].split(' ')[0],
                    'exchange': record['data'].split(' ')[1],
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_SRV(self, _type, records):
        values = []
        for record in records:

            values.append(
                {
                    'port': record['data'].split(' ')[2],
                    'priority': record['data'].split(' ')[0],
                    'target': record['data'].split(' ')[3],
                    'weight': record['data'].split(' ')[1],
                }
            )
        return {'type': _type, 'ttl': records[0]['ttl'], 'values': values}

    def _data_for_DS(self, _type, records):
        values = []
        for record in records:
            values.append(
                {
                    'key_tag': record['data'].split(' ')[0],
                    'algorithm': record['data'].split(' ')[1],
                    'digest_type': record['data'].split(' ')[2],
                    'digest': record['data'].split(' ')[3],
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_CAA(self, _type, records):
        values = []
        for record in records:
            values.append(
                {
                    'flags': record['data']
                    .split(' ')[0]
                    .lstrip('"')
                    .rstrip('"'),
                    'tag': record['data'].split(' ')[1].lstrip('"').rstrip('"'),
                    'value': record['data']
                    .split(' ')[2]
                    .lstrip('"')
                    .strip('"'),
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_TLSA(self, _type, records):
        values = []
        for record in records:
            values.append(
                {
                    'certificate_usage': record['data'].split(' ')[0],
                    'selector': record['data'].split(' ')[1],
                    'matching_type': record['data'].split(' ')[2],
                    'certificate_association_data': record['data'].split(' ')[
                        3
                    ],
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_HTTPS(self, _type, records):
        values = []
        for record in records:
            svcparams = {}
            if len(record['data'].split(' ')) > 2:
                # iterate over all elements from index 2 to $last
                for parameter in record['data'].split(' ')[2:]:
                    k,v = parameter.split('=', maxsplit=1)
                    # convert some parameters to list
                    if k in ('alpn', 'ipv4hint', 'ipv6hint') :
                        v = v.split(',')
                    svcparams[k] = v

            values.append(
                {
                    'svcpriority': record['data'].split(' ')[0],
                    'targetname': record['data'].split(' ')[1],
                    'svcparams': svcparams
                }
            )
        return {'type': _type, 'ttl': records[0]['ttl'], 'values': values}

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_CNAME = _data_for_single
    _data_for_NS = _data_for_multiple
    _data_for_PTR = _data_for_single
