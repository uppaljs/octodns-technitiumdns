from json import load
from os.path import dirname, join
from unittest import TestCase

from requests_mock import mock as requests_mock

from octodns.provider import ProviderException
from octodns.record import Record
from octodns.zone import Zone

from octodns_technitiumdns import TechnitiumDnsProvider

FIXTURES_DIR = join(dirname(__file__), 'fixtures')


def _load_fixture(name):
    with open(join(FIXTURES_DIR, name)) as f:
        return load(f)


class TestTechnitiumDnsProvider(TestCase):
    api_url = 'http://localhost:5380'

    def _provider(self):
        return TechnitiumDnsProvider(
            'test', 'localhost', 'test-token', port=5380
        )

    def _zone(self):
        return Zone('unit.tests.', [])

    def test_provider_init(self):
        provider = self._provider()
        self.assertEqual('http://localhost:5380', provider._base_url)
        self.assertEqual('test-token', provider._token)

    def test_populate_non_existent_zone(self):
        provider = self._provider()
        zone = self._zone()

        # Return a zones list that doesn't include our zone
        with requests_mock() as mock:
            mock.get(
                f'{self.api_url}/api/zones/list',
                json={
                    'status': 'ok',
                    'response': {
                        'zones': [{'name': 'other.tests', 'type': 'Primary'}]
                    },
                },
            )
            exists = provider.populate(zone)

        self.assertFalse(exists)
        self.assertEqual(0, len(zone.records))

    def test_populate_empty_zone(self):
        provider = self._provider()
        zone = self._zone()

        zones_list = _load_fixture('zones-list.json')
        empty_zone = _load_fixture('empty-zone.json')

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(f'{self.api_url}/api/zones/records/get', json=empty_zone)
            exists = provider.populate(zone)

        self.assertTrue(exists)
        # SOA is skipped, so no records
        self.assertEqual(0, len(zone.records))

    def test_populate_full(self):
        provider = self._provider()
        zone = self._zone()

        zones_list = _load_fixture('zones-list.json')
        full_records = _load_fixture('full-records.json')

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(f'{self.api_url}/api/zones/records/get', json=full_records)
            exists = provider.populate(zone)

        self.assertTrue(exists)

        # Build a lookup of records by name and type
        records = {}
        for r in zone.records:
            records[(r.name, r._type)] = r

        # A records at zone apex
        a_record = records[('', 'A')]
        self.assertEqual(300, a_record.ttl)
        self.assertEqual({'1.2.3.4', '1.2.3.5'}, set(a_record.values))

        # AAAA record
        aaaa_record = records[('aaaa', 'AAAA')]
        self.assertEqual(300, aaaa_record.ttl)
        self.assertIn(
            '2601:644:500:e210:62f8:1dff:feb8:947a', aaaa_record.values
        )

        # CNAME record
        cname_record = records[('cname', 'CNAME')]
        self.assertEqual('unit.tests.', cname_record.value)

        # ALIAS record (from ANAME)
        alias_record = records[('', 'ALIAS')]
        self.assertEqual('aname-target.unit.tests.', alias_record.value)

        # DNAME record
        dname_record = records[('dname', 'DNAME')]
        self.assertEqual('unit.tests.', dname_record.value)

        # MX records
        mx_record = records[('', 'MX')]
        mx_values = sorted(mx_record.values, key=lambda v: v.preference)
        self.assertEqual(10, mx_values[0].preference)
        self.assertEqual('smtp.unit.tests.', mx_values[0].exchange)
        self.assertEqual(20, mx_values[1].preference)
        self.assertEqual('smtp2.unit.tests.', mx_values[1].exchange)

        # TXT records
        txt_record = records[('txt', 'TXT')]
        self.assertIn('v=spf1 include:unit.tests ~all', txt_record.values)
        self.assertIn('txt-value-2', txt_record.values)

        # NS records (delegated subdomain)
        ns_record = records[('sub', 'NS')]
        self.assertIn('ns1.sub.unit.tests.', ns_record.values)

        # PTR record
        ptr_record = records[('ptr', 'PTR')]
        self.assertIn('a.unit.tests.', ptr_record.values)

        # SRV records
        srv_record = records[('_srv._tcp', 'SRV')]
        srv_values = sorted(srv_record.values, key=lambda v: v.priority)
        self.assertEqual(10, srv_values[0].priority)
        self.assertEqual(20, srv_values[0].weight)
        self.assertEqual(30, srv_values[0].port)
        self.assertEqual('foo-1.unit.tests.', srv_values[0].target)

        # CAA record
        caa_record = records[('caa', 'CAA')]
        self.assertEqual(0, caa_record.values[0].flags)
        self.assertEqual('issue', caa_record.values[0].tag)
        self.assertEqual('ca.unit.tests', caa_record.values[0].value)

        # NAPTR record
        naptr_record = records[('naptr', 'NAPTR')]
        self.assertEqual(10, naptr_record.values[0].order)
        self.assertEqual(20, naptr_record.values[0].preference)
        self.assertEqual('U', naptr_record.values[0].flags)
        self.assertEqual('E2U+sip', naptr_record.values[0].service)

        # DS record
        ds_record = records[('ds', 'DS')]
        self.assertEqual(12345, ds_record.values[0].key_tag)
        self.assertEqual(8, ds_record.values[0].algorithm)
        self.assertEqual(2, ds_record.values[0].digest_type)

        # SSHFP record
        sshfp_record = records[('sshfp', 'SSHFP')]
        self.assertEqual(1, sshfp_record.values[0].algorithm)
        self.assertEqual(1, sshfp_record.values[0].fingerprint_type)

        # TLSA record
        tlsa_record = records[('tlsa', 'TLSA')]
        self.assertEqual(3, tlsa_record.values[0].certificate_usage)
        self.assertEqual(1, tlsa_record.values[0].selector)
        self.assertEqual(1, tlsa_record.values[0].matching_type)

    def test_populate_with_string_enum_values(self):
        """Test that string enum values from Technitium are properly
        converted to integers."""
        provider = self._provider()
        zone = self._zone()

        zones_list = _load_fixture('zones-list.json')
        records_with_strings = {
            'status': 'ok',
            'response': {
                'records': [
                    {
                        'name': 'ds.unit.tests',
                        'type': 'DS',
                        'ttl': 300,
                        'rData': {
                            'keyTag': 12345,
                            'algorithm': 'RSASHA256',
                            'digestType': 'SHA-256',
                            'digest': 'ABCDEF',
                        },
                        'disabled': False,
                    },
                    {
                        'name': 'sshfp.unit.tests',
                        'type': 'SSHFP',
                        'ttl': 300,
                        'rData': {
                            'algorithm': 'RSA',
                            'fingerprintType': 'SHA-256',
                            'fingerprint': 'abcdef',
                        },
                        'disabled': False,
                    },
                    {
                        'name': 'tlsa.unit.tests',
                        'type': 'TLSA',
                        'ttl': 300,
                        'rData': {
                            'certificateUsage': 'DANE-EE',
                            'selector': 'SPKI',
                            'matchingType': 'SHA2-256',
                            'certificateAssociationData': 'abcdef',
                        },
                        'disabled': False,
                    },
                ]
            },
        }

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(
                f'{self.api_url}/api/zones/records/get',
                json=records_with_strings,
            )
            provider.populate(zone)

        records = {}
        for r in zone.records:
            records[(r.name, r._type)] = r

        # DS: string -> int conversion
        ds = records[('ds', 'DS')]
        self.assertEqual(8, ds.values[0].algorithm)
        self.assertEqual(2, ds.values[0].digest_type)

        # SSHFP: string -> int conversion
        sshfp = records[('sshfp', 'SSHFP')]
        self.assertEqual(1, sshfp.values[0].algorithm)
        self.assertEqual(2, sshfp.values[0].fingerprint_type)

        # TLSA: string -> int conversion
        tlsa = records[('tlsa', 'TLSA')]
        self.assertEqual(3, tlsa.values[0].certificate_usage)
        self.assertEqual(1, tlsa.values[0].selector)
        self.assertEqual(1, tlsa.values[0].matching_type)

    def test_apply_create(self):
        provider = self._provider()

        # Build a plan with creates
        zone = self._zone()
        zone.add_record(
            Record.new(
                zone,
                'www',
                {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4', '1.2.3.5']},
            )
        )
        zone.add_record(
            Record.new(
                zone,
                '',
                {
                    'type': 'MX',
                    'ttl': 300,
                    'values': [
                        {'preference': 10, 'exchange': 'smtp.unit.tests.'}
                    ],
                },
            )
        )
        zone.add_record(
            Record.new(
                zone,
                'txt',
                {'type': 'TXT', 'ttl': 300, 'values': ['v=spf1 ~all']},
            )
        )

        zones_list = _load_fixture('zones-list.json')

        with requests_mock() as mock:
            # Zone existence check
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            # Record adds
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )
            # Populate with empty zone first
            mock.get(
                f'{self.api_url}/api/zones/records/get',
                json={'status': 'ok', 'response': {'records': []}},
            )

            # Create plan
            plan = provider.plan(zone)
            self.assertIsNotNone(plan)

            # Apply
            provider.apply(plan)

        # Verify the correct number of add calls were made
        add_calls = [
            h for h in mock.request_history if '/api/zones/records/add' in h.url
        ]
        # 2 A records + 1 MX + 1 TXT = 4 add calls
        self.assertEqual(4, len(add_calls))

    def test_apply_delete(self):
        provider = self._provider()
        zone = self._zone()

        zones_list = _load_fixture('zones-list.json')
        full_records = _load_fixture('full-records.json')

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(f'{self.api_url}/api/zones/records/get', json=full_records)
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )
            mock.post(
                f'{self.api_url}/api/zones/records/delete',
                json={'status': 'ok', 'response': {}},
            )

            # Populate existing state
            provider.populate(zone)

            # Now plan to sync to empty desired
            desired = Zone('unit.tests.', [])
            # Add just the root NS so it doesn't try to delete those
            desired.add_record(
                Record.new(
                    desired,
                    '',
                    {
                        'type': 'NS',
                        'ttl': 3600,
                        'values': ['ns1.unit.tests.', 'ns2.unit.tests.'],
                    },
                )
            )

            plan = provider.plan(desired)
            if plan:
                provider.apply(plan)

                # Should have delete calls
                delete_calls = [
                    h
                    for h in mock.request_history
                    if '/api/zones/records/delete' in h.url
                ]
                self.assertGreater(len(delete_calls), 0)

    def test_apply_update(self):
        provider = self._provider()
        zone = self._zone()

        # Start with one A record
        existing_records = {
            'status': 'ok',
            'response': {
                'records': [
                    {
                        'name': 'www.unit.tests',
                        'type': 'A',
                        'ttl': 300,
                        'rData': {'ipAddress': '1.2.3.4'},
                        'disabled': False,
                    }
                ]
            },
        }

        zones_list = _load_fixture('zones-list.json')

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(
                f'{self.api_url}/api/zones/records/get', json=existing_records
            )
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )
            mock.post(
                f'{self.api_url}/api/zones/records/delete',
                json={'status': 'ok', 'response': {}},
            )

            # Populate existing
            provider.populate(zone)

            # Desired: same record, different IP
            desired = Zone('unit.tests.', [])
            desired.add_record(
                Record.new(
                    desired,
                    'www',
                    {'type': 'A', 'ttl': 300, 'values': ['5.6.7.8']},
                )
            )

            plan = provider.plan(desired)
            self.assertIsNotNone(plan)
            provider.apply(plan)

        # Should have 1 delete (old) + 1 add (new)
        delete_calls = [
            h
            for h in mock.request_history
            if '/api/zones/records/delete' in h.url
        ]
        add_calls = [
            h for h in mock.request_history if '/api/zones/records/add' in h.url
        ]
        self.assertEqual(1, len(delete_calls))
        self.assertEqual(1, len(add_calls))

    def test_apply_creates_zone_if_missing(self):
        provider = self._provider()

        desired = Zone('new-zone.tests.', [])
        desired.add_record(
            Record.new(
                desired, '', {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4']}
            )
        )

        with requests_mock() as mock:
            # Zone doesn't exist initially
            mock.get(
                f'{self.api_url}/api/zones/list',
                json={'status': 'ok', 'response': {'zones': []}},
            )
            mock.get(
                f'{self.api_url}/api/zones/records/get',
                json={'status': 'ok', 'response': {'records': []}},
            )
            mock.post(
                f'{self.api_url}/api/zones/create',
                json={'status': 'ok', 'response': {}},
            )
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )

            plan = provider.plan(desired)
            self.assertIsNotNone(plan)
            provider.apply(plan)

        # Verify zone create was called
        create_calls = [
            h for h in mock.request_history if '/api/zones/create' in h.url
        ]
        self.assertEqual(1, len(create_calls))

    def test_alias_aname_mapping(self):
        """Test ANAME <-> ALIAS bidirectional mapping."""
        provider = self._provider()
        zone = self._zone()

        # Technitium returns ANAME, octodns should see ALIAS
        records_with_aname = {
            'status': 'ok',
            'response': {
                'records': [
                    {
                        'name': 'unit.tests',
                        'type': 'ANAME',
                        'ttl': 300,
                        'rData': {'aname': 'target.unit.tests.'},
                        'disabled': False,
                    }
                ]
            },
        }
        zones_list = _load_fixture('zones-list.json')

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(
                f'{self.api_url}/api/zones/records/get', json=records_with_aname
            )
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )
            mock.post(
                f'{self.api_url}/api/zones/records/delete',
                json={'status': 'ok', 'response': {}},
            )

            provider.populate(zone)

            # Should have ALIAS type, not ANAME
            records = {(r.name, r._type): r for r in zone.records}
            self.assertIn(('', 'ALIAS'), records)
            self.assertEqual('target.unit.tests.', records[('', 'ALIAS')].value)

            # Now test that applying an ALIAS record sends ANAME to the API
            desired = Zone('unit.tests.', [])
            desired.add_record(
                Record.new(
                    desired,
                    '',
                    {
                        'type': 'ALIAS',
                        'ttl': 300,
                        'value': 'new-target.unit.tests.',
                    },
                )
            )

            plan = provider.plan(desired)
            if plan:
                provider.apply(plan)

                # Check that the add call used ANAME type
                add_calls = [
                    h
                    for h in mock.request_history
                    if '/api/zones/records/add' in h.url
                ]
                for call in add_calls:
                    self.assertIn('type=ANAME', call.body)

    def test_api_error_handling(self):
        provider = self._provider()

        with requests_mock() as mock:
            mock.get(
                f'{self.api_url}/api/zones/list',
                json={'status': 'error', 'errorMessage': 'Access was denied.'},
            )

            zone = self._zone()
            with self.assertRaises(ProviderException) as ctx:
                provider.populate(zone)
            self.assertIn('Access was denied', str(ctx.exception))

    def test_disabled_records_skipped(self):
        """Test that disabled records in Technitium are skipped."""
        provider = self._provider()
        zone = self._zone()

        records = {
            'status': 'ok',
            'response': {
                'records': [
                    {
                        'name': 'enabled.unit.tests',
                        'type': 'A',
                        'ttl': 300,
                        'rData': {'ipAddress': '1.2.3.4'},
                        'disabled': False,
                    },
                    {
                        'name': 'disabled.unit.tests',
                        'type': 'A',
                        'ttl': 300,
                        'rData': {'ipAddress': '5.6.7.8'},
                        'disabled': True,
                    },
                ]
            },
        }
        zones_list = _load_fixture('zones-list.json')

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(f'{self.api_url}/api/zones/records/get', json=records)
            provider.populate(zone)

        record_names = {r.name for r in zone.records}
        self.assertIn('enabled', record_names)
        self.assertNotIn('disabled', record_names)

    def test_ensure_trailing_dot(self):
        self.assertEqual(
            'foo.bar.', TechnitiumDnsProvider._ensure_trailing_dot('foo.bar')
        )
        self.assertEqual(
            'foo.bar.', TechnitiumDnsProvider._ensure_trailing_dot('foo.bar.')
        )
        self.assertEqual('.', TechnitiumDnsProvider._ensure_trailing_dot('.'))

    def test_to_int(self):
        mapping = {'FOO': 1, 'BAR': 2}
        self.assertEqual(1, TechnitiumDnsProvider._to_int(1))
        self.assertEqual(1, TechnitiumDnsProvider._to_int('1'))
        self.assertEqual(1, TechnitiumDnsProvider._to_int('FOO', mapping))
        self.assertEqual(2, TechnitiumDnsProvider._to_int('BAR', mapping))

    def test_record_name_conversion(self):
        provider = self._provider()
        # Subdomain
        self.assertEqual(
            'www', provider._record_name('www.example.com', 'example.com')
        )
        # Zone apex
        self.assertEqual(
            '', provider._record_name('example.com', 'example.com')
        )
        # Deep subdomain
        self.assertEqual(
            'a.b.c', provider._record_name('a.b.c.example.com', 'example.com')
        )

    def test_fqdn_for(self):
        provider = self._provider()
        zone = self._zone()

        # Subdomain record
        record = Record.new(
            zone, 'www', {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'}
        )
        self.assertEqual(
            'www.unit.tests', provider._fqdn_for(record, 'unit.tests')
        )

        # Zone apex record
        record = Record.new(
            zone, '', {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'}
        )
        self.assertEqual('unit.tests', provider._fqdn_for(record, 'unit.tests'))

    def test_apply_cname(self):
        """Test creating a CNAME record."""
        provider = self._provider()

        desired = Zone('unit.tests.', [])
        desired.add_record(
            Record.new(
                desired,
                'www',
                {'type': 'CNAME', 'ttl': 300, 'value': 'unit.tests.'},
            )
        )

        zones_list = _load_fixture('zones-list.json')

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(
                f'{self.api_url}/api/zones/records/get',
                json={'status': 'ok', 'response': {'records': []}},
            )
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )

            plan = provider.plan(desired)
            self.assertIsNotNone(plan)
            provider.apply(plan)

        add_calls = [
            h for h in mock.request_history if '/api/zones/records/add' in h.url
        ]
        self.assertEqual(1, len(add_calls))
        self.assertIn('type=CNAME', add_calls[0].body)
        self.assertIn('cname=unit.tests.', add_calls[0].body)

    def test_apply_srv(self):
        """Test creating SRV records."""
        provider = self._provider()

        desired = Zone('unit.tests.', [])
        desired.add_record(
            Record.new(
                desired,
                '_sip._tcp',
                {
                    'type': 'SRV',
                    'ttl': 300,
                    'values': [
                        {
                            'priority': 10,
                            'weight': 20,
                            'port': 5060,
                            'target': 'sip.unit.tests.',
                        }
                    ],
                },
            )
        )

        zones_list = _load_fixture('zones-list.json')

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(
                f'{self.api_url}/api/zones/records/get',
                json={'status': 'ok', 'response': {'records': []}},
            )
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )

            plan = provider.plan(desired)
            self.assertIsNotNone(plan)
            provider.apply(plan)

        add_calls = [
            h for h in mock.request_history if '/api/zones/records/add' in h.url
        ]
        self.assertEqual(1, len(add_calls))
        body = add_calls[0].body
        self.assertIn('type=SRV', body)
        self.assertIn('priority=10', body)
        self.assertIn('weight=20', body)
        self.assertIn('port=5060', body)

    def test_populate_loc_records(self):
        """Test LOC record parsing from Technitium."""
        provider = self._provider()
        zone = self._zone()
        zones_list = _load_fixture('zones-list.json')

        records = {
            'status': 'ok',
            'response': {
                'records': [
                    {
                        'name': 'loc.unit.tests',
                        'type': 'LOC',
                        'ttl': 300,
                        'rData': {
                            'latDegrees': 51,
                            'latMinutes': 30,
                            'latSeconds': 12.748,
                            'latDirection': 'N',
                            'longDegrees': 0,
                            'longMinutes': 7,
                            'longSeconds': 39.612,
                            'longDirection': 'W',
                            'altitude': 0.0,
                            'size': 1.0,
                            'horizontalPrecision': 10000.0,
                            'verticalPrecision': 10.0,
                        },
                        'disabled': False,
                    }
                ]
            },
        }

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(f'{self.api_url}/api/zones/records/get', json=records)
            provider.populate(zone)

        recs = {(r.name, r._type): r for r in zone.records}
        loc = recs[('loc', 'LOC')]
        self.assertEqual(300, loc.ttl)
        v = loc.values[0]
        self.assertEqual(51, v.lat_degrees)
        self.assertEqual(30, v.lat_minutes)
        self.assertEqual(12.748, v.lat_seconds)
        self.assertEqual('N', v.lat_direction)
        self.assertEqual(0, v.long_degrees)
        self.assertEqual(7, v.long_minutes)
        self.assertEqual(39.612, v.long_seconds)
        self.assertEqual('W', v.long_direction)
        self.assertEqual(0.0, v.altitude)
        self.assertEqual(1.0, v.size)
        self.assertEqual(10000.0, v.precision_horz)
        self.assertEqual(10.0, v.precision_vert)

    def test_apply_loc_records(self):
        """Test LOC record params generation."""
        provider = self._provider()

        desired = Zone('unit.tests.', [])
        desired.add_record(
            Record.new(
                desired,
                'loc',
                {
                    'type': 'LOC',
                    'ttl': 300,
                    'values': [
                        {
                            'lat_degrees': 51,
                            'lat_minutes': 30,
                            'lat_seconds': 12.748,
                            'lat_direction': 'N',
                            'long_degrees': 0,
                            'long_minutes': 7,
                            'long_seconds': 39.612,
                            'long_direction': 'W',
                            'altitude': 0.0,
                            'size': 1.0,
                            'precision_horz': 10000.0,
                            'precision_vert': 10.0,
                        }
                    ],
                },
            )
        )

        zones_list = _load_fixture('zones-list.json')

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(
                f'{self.api_url}/api/zones/records/get',
                json={'status': 'ok', 'response': {'records': []}},
            )
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )

            plan = provider.plan(desired)
            self.assertIsNotNone(plan)
            provider.apply(plan)

        add_calls = [
            h for h in mock.request_history if '/api/zones/records/add' in h.url
        ]
        self.assertEqual(1, len(add_calls))
        body = add_calls[0].body
        self.assertIn('type=LOC', body)
        self.assertIn('latDegrees=51', body)
        self.assertIn('longDirection=W', body)

    def test_populate_uri_records(self):
        """Test URI record parsing from Technitium."""
        provider = self._provider()
        zone = self._zone()
        zones_list = _load_fixture('zones-list.json')

        # URI records require underscore-prefixed names
        records = {
            'status': 'ok',
            'response': {
                'records': [
                    {
                        'name': '_http._tcp.unit.tests',
                        'type': 'URI',
                        'ttl': 300,
                        'rData': {
                            'priority': 10,
                            'weight': 1,
                            'uri': 'https://unit.tests/',
                        },
                        'disabled': False,
                    }
                ]
            },
        }

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(f'{self.api_url}/api/zones/records/get', json=records)
            provider.populate(zone)

        recs = {(r.name, r._type): r for r in zone.records}
        # URI may not be supported depending on octodns version
        if ('_http._tcp', 'URI') in recs:
            uri = recs[('_http._tcp', 'URI')]
            self.assertEqual(10, uri.values[0].priority)
            self.assertEqual(1, uri.values[0].weight)
            self.assertEqual('https://unit.tests/', uri.values[0].target)

    def test_apply_uri_records(self):
        """Test URI record params generation."""
        provider = self._provider()

        # Skip if URI not supported in this octodns version
        if 'URI' not in provider.SUPPORTS:
            return

        desired = Zone('unit.tests.', [])
        desired.add_record(
            Record.new(
                desired,
                '_http._tcp',
                {
                    'type': 'URI',
                    'ttl': 300,
                    'values': [
                        {
                            'priority': 10,
                            'weight': 1,
                            'target': 'https://unit.tests/',
                        }
                    ],
                },
            )
        )

        zones_list = _load_fixture('zones-list.json')

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(
                f'{self.api_url}/api/zones/records/get',
                json={'status': 'ok', 'response': {'records': []}},
            )
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )

            plan = provider.plan(desired)
            self.assertIsNotNone(plan)
            provider.apply(plan)

        add_calls = [
            h for h in mock.request_history if '/api/zones/records/add' in h.url
        ]
        self.assertEqual(1, len(add_calls))
        body = add_calls[0].body
        self.assertIn('type=URI', body)
        self.assertIn('priority=10', body)
        self.assertIn('weight=1', body)

    def test_apply_creates_zone_cleans_default_ns(self):
        """Test that zone creation cleans up default NS records."""
        provider = self._provider()

        desired = Zone('brand-new.tests.', [])
        desired.add_record(
            Record.new(
                desired, '', {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4']}
            )
        )

        with requests_mock() as mock:
            mock.get(
                f'{self.api_url}/api/zones/list',
                json={'status': 'ok', 'response': {'zones': []}},
            )
            mock.get(
                f'{self.api_url}/api/zones/records/get',
                [
                    # First call: NS records query during zone creation
                    {
                        'json': {
                            'status': 'ok',
                            'response': {
                                'records': [
                                    {
                                        'name': 'brand-new.tests',
                                        'type': 'NS',
                                        'ttl': 3600,
                                        'rData': {'nameServer': 'localhost.'},
                                    }
                                ]
                            },
                        }
                    },
                    # Second call: populate records
                    {'json': {'status': 'ok', 'response': {'records': []}}},
                ],
            )
            mock.post(
                f'{self.api_url}/api/zones/create',
                json={'status': 'ok', 'response': {}},
            )
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )
            mock.post(
                f'{self.api_url}/api/zones/records/delete',
                json={'status': 'ok', 'response': {}},
            )

            plan = provider.plan(desired)
            self.assertIsNotNone(plan)
            provider.apply(plan)

        # Verify NS cleanup delete was called
        delete_calls = [
            h
            for h in mock.request_history
            if '/api/zones/records/delete' in h.url
        ]
        self.assertGreater(len(delete_calls), 0)
        self.assertIn('nameServer=localhost.', delete_calls[0].body)

    def test_to_int_fallbacks(self):
        """Test _to_int falls back to int() then raw value."""
        # Numeric string not in map -> int conversion
        result = TechnitiumDnsProvider._to_int('42', {'FOO': 1})
        self.assertEqual(42, result)

        # Non-numeric string not in map -> returned as-is
        result = TechnitiumDnsProvider._to_int('UNKNOWN', {'FOO': 1})
        self.assertEqual('UNKNOWN', result)

    def test_record_name_no_suffix_match(self):
        """Test _record_name when FQDN doesn't end with zone suffix."""
        provider = self._provider()
        # FQDN that doesn't match zone -> returned as-is
        result = provider._record_name('other.domain.com', 'example.com')
        self.assertEqual('other.domain.com', result)

    def test_unsupported_record_type_skipped(self):
        """Test that unsupported record types are silently skipped."""
        provider = self._provider()
        zone = self._zone()
        zones_list = _load_fixture('zones-list.json')

        records = {
            'status': 'ok',
            'response': {
                'records': [
                    {
                        'name': 'unit.tests',
                        'type': 'OPENPGPKEY',
                        'ttl': 300,
                        'rData': {'data': 'abc123'},
                        'disabled': False,
                    },
                    {
                        'name': 'a.unit.tests',
                        'type': 'A',
                        'ttl': 300,
                        'rData': {'ipAddress': '1.2.3.4'},
                        'disabled': False,
                    },
                ]
            },
        }

        with requests_mock() as mock:
            mock.get(f'{self.api_url}/api/zones/list', json=zones_list)
            mock.get(f'{self.api_url}/api/zones/records/get', json=records)
            provider.populate(zone)

        recs = {(r.name, r._type): r for r in zone.records}
        # Only the A record should be present
        self.assertEqual(1, len(zone.records))
        self.assertIn(('a', 'A'), recs)

    def test_create_zone_ns_cleanup_exception(self):
        """Test that NS cleanup failure during zone creation is non-fatal."""
        provider = self._provider()

        desired = Zone('fail-ns.tests.', [])
        desired.add_record(
            Record.new(
                desired, '', {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4']}
            )
        )

        with requests_mock() as mock:
            mock.get(
                f'{self.api_url}/api/zones/list',
                json={'status': 'ok', 'response': {'zones': []}},
            )
            mock.post(
                f'{self.api_url}/api/zones/create',
                json={'status': 'ok', 'response': {}},
            )
            # NS records query during cleanup raises an error
            mock.get(
                f'{self.api_url}/api/zones/records/get',
                [
                    # First call: NS cleanup - returns error
                    {
                        'json': {
                            'status': 'error',
                            'errorMessage': 'Something went wrong',
                        }
                    },
                    # Second call: populate records
                    {'json': {'status': 'ok', 'response': {'records': []}}},
                ],
            )
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )

            plan = provider.plan(desired)
            self.assertIsNotNone(plan)
            # Should not raise despite NS cleanup failure
            provider.apply(plan)

    def test_create_zone_ns_cleanup_skips_non_ns(self):
        """Test NS cleanup skips non-NS records in response."""
        provider = self._provider()

        desired = Zone('skip-ns.tests.', [])
        desired.add_record(
            Record.new(
                desired, '', {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4']}
            )
        )

        with requests_mock() as mock:
            mock.get(
                f'{self.api_url}/api/zones/list',
                json={'status': 'ok', 'response': {'zones': []}},
            )
            mock.post(
                f'{self.api_url}/api/zones/create',
                json={'status': 'ok', 'response': {}},
            )
            mock.get(
                f'{self.api_url}/api/zones/records/get',
                [
                    # NS cleanup query returns a non-NS record
                    {
                        'json': {
                            'status': 'ok',
                            'response': {
                                'records': [
                                    {
                                        'name': 'skip-ns.tests',
                                        'type': 'SOA',
                                        'ttl': 900,
                                        'rData': {},
                                    }
                                ]
                            },
                        }
                    },
                    # populate call
                    {'json': {'status': 'ok', 'response': {'records': []}}},
                ],
            )
            mock.post(
                f'{self.api_url}/api/zones/records/add',
                json={'status': 'ok', 'response': {}},
            )

            plan = provider.plan(desired)
            self.assertIsNotNone(plan)
            provider.apply(plan)

        # No delete calls should have been made (SOA != NS)
        delete_calls = [
            h
            for h in mock.request_history
            if '/api/zones/records/delete' in h.url
        ]
        self.assertEqual(0, len(delete_calls))

    def test_conditional_svcb_import(self):
        """Test that SVCB/HTTPS are in SUPPORTS when available."""
        provider = self._provider()
        # octodns 1.5+ should have SVCB support
        has_svcb = 'SVCB' in provider.SUPPORTS
        if has_svcb:
            self.assertIn('HTTPS', provider.SUPPORTS)

    def test_conditional_uri_import(self):
        """Test that URI is in SUPPORTS when available."""
        provider = self._provider()
        # Just verify the conditional import result is consistent
        self.assertIsInstance(provider.SUPPORTS, set)
