#
#
#

from unittest import TestCase

from octodns_desec import DesecProvider

# synthetic Base64 (decodes to ASCII), not a real ECHConfigList
ECH_PAD1 = 'ZmFrZS1lY2gtY29uZmlnISE='  # single '=' padding
ECH_PAD2 = 'ZmFrZS1lY2gtY29uZmlnIQ=='  # double '==' padding


class TestDesecProvider(TestCase):
    # TODO: test provider
    def test_nothing(self):
        self.assertTrue(True)
        DesecProvider

    def _https_values(self, *data):
        provider = DesecProvider.__new__(DesecProvider)
        records = [{'ttl': 3600, 'data': d} for d in data]
        return provider._data_for_HTTPS('HTTPS', records)['values']

    def test_data_for_https_ech_quoted(self):
        # deSEC returns ech in presentation format, i.e. double-quoted
        values = self._https_values(f'2 . alpn=h3,h2 ech="{ECH_PAD1}"')
        self.assertEqual(
            {'alpn': ['h3', 'h2'], 'ech': ECH_PAD1}, values[0]['svcparams']
        )

    def test_data_for_https_ech_padding(self):
        values = self._https_values(
            f'1 . ech="{ECH_PAD2}"', f'1 . ech="{ECH_PAD1}"'
        )
        self.assertEqual(ECH_PAD2, values[0]['svcparams']['ech'])
        self.assertEqual(ECH_PAD1, values[1]['svcparams']['ech'])

    def test_data_for_https_ech_unquoted(self):
        values = self._https_values(f'2 . ech={ECH_PAD1}')
        self.assertEqual({'ech': ECH_PAD1}, values[0]['svcparams'])

    def test_data_for_https_ech_unbalanced_quotes(self):
        # only a balanced pair of quotes is presentation syntax
        values = self._https_values(
            f'1 . ech="{ECH_PAD1}', f'1 . ech={ECH_PAD1}"', '1 . ech="'
        )
        self.assertEqual(f'"{ECH_PAD1}', values[0]['svcparams']['ech'])
        self.assertEqual(f'{ECH_PAD1}"', values[1]['svcparams']['ech'])
        self.assertEqual('"', values[2]['svcparams']['ech'])

    def test_data_for_https_no_ech(self):
        values = self._https_values('1 . alpn=h2', '0 target.example.com.')
        self.assertEqual({'alpn': ['h2']}, values[0]['svcparams'])
        self.assertEqual({}, values[1]['svcparams'])
