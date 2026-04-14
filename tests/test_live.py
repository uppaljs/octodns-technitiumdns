"""
Live integration tests against a Technitium DNS server.

Run with:
    TECHNITIUM_HOST=192.168.88.78 TECHNITIUM_TOKEN=xxx python -m pytest tests/test_live.py -v -s

These tests create/modify/delete records in a test zone.
"""

import os
from unittest import TestCase, skipUnless

from octodns.record import Record
from octodns.zone import Zone

from octodns_technitiumdns import TechnitiumDnsProvider

HOST = os.environ.get('TECHNITIUM_HOST')
TOKEN = os.environ.get('TECHNITIUM_TOKEN')
TEST_ZONE = 'octodns-live-test.example.'


@skipUnless(HOST and TOKEN, 'TECHNITIUM_HOST and TECHNITIUM_TOKEN required')
class TestLiveProvider(TestCase):
    def _provider(self):
        return TechnitiumDnsProvider('live-test', HOST, TOKEN, port=5380)

    def _cleanup_zone(self, provider, zone_name):
        """Delete the test zone if it exists."""
        try:
            provider._post(
                'api/zones/delete', {'domain': zone_name, 'deleteZone': 'true'}
            )
        except Exception:
            pass

    def setUp(self):
        self.provider = self._provider()
        self.zone_name = TEST_ZONE[:-1]  # strip trailing dot
        self._cleanup_zone(self.provider, self.zone_name)

    def tearDown(self):
        self._cleanup_zone(self.provider, self.zone_name)

    def test_full_lifecycle(self):
        """Test create zone -> populate empty -> add records -> populate
        -> update records -> delete records."""
        provider = self.provider
        zone = Zone(TEST_ZONE, [])

        # 1. Populate non-existent zone returns False
        exists = provider.populate(zone)
        self.assertFalse(exists)
        self.assertEqual(0, len(zone.records))

        # 2. Create zone with records via apply
        desired = Zone(TEST_ZONE, [])
        desired.add_record(
            Record.new(
                desired,
                'www',
                {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4', '5.6.7.8']},
            )
        )
        desired.add_record(
            Record.new(
                desired,
                'ipv6',
                {'type': 'AAAA', 'ttl': 300, 'values': ['2001:db8::1']},
            )
        )
        desired.add_record(
            Record.new(
                desired,
                'mail',
                {'type': 'CNAME', 'ttl': 300, 'value': f'www.{TEST_ZONE}'},
            )
        )
        desired.add_record(
            Record.new(
                desired,
                '',
                {
                    'type': 'MX',
                    'ttl': 300,
                    'values': [
                        {'preference': 10, 'exchange': f'smtp.{TEST_ZONE}'},
                        {'preference': 20, 'exchange': f'smtp2.{TEST_ZONE}'},
                    ],
                },
            )
        )
        desired.add_record(
            Record.new(
                desired,
                'txt',
                {
                    'type': 'TXT',
                    'ttl': 300,
                    'values': ['v=spf1 ~all', 'some-other-txt'],
                },
            )
        )
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
                            'target': f'sip.{TEST_ZONE}',
                        }
                    ],
                },
            )
        )
        desired.add_record(
            Record.new(
                desired,
                '',
                {
                    'type': 'CAA',
                    'ttl': 300,
                    'values': [
                        {'flags': 0, 'tag': 'issue', 'value': 'letsencrypt.org'}
                    ],
                },
            )
        )
        desired.add_record(
            Record.new(
                desired,
                'naptr',
                {
                    'type': 'NAPTR',
                    'ttl': 300,
                    'values': [
                        {
                            'order': 100,
                            'preference': 10,
                            'flags': 'S',
                            'service': 'SIP+D2U',
                            'regexp': '',
                            'replacement': f'_sip._udp.{TEST_ZONE}',
                        }
                    ],
                },
            )
        )
        desired.add_record(
            Record.new(
                desired,
                '',
                {
                    'type': 'NS',
                    'ttl': 3600,
                    'values': [f'ns1.{TEST_ZONE}', f'ns2.{TEST_ZONE}'],
                },
            )
        )

        plan = provider.plan(desired)
        self.assertIsNotNone(plan)
        provider.apply(plan)

        # 3. Re-populate and verify records match
        zone2 = Zone(TEST_ZONE, [])
        exists = provider.populate(zone2)
        self.assertTrue(exists)

        records = {(r.name, r._type): r for r in zone2.records}

        # Verify A records
        self.assertIn(('www', 'A'), records)
        self.assertEqual(
            {'1.2.3.4', '5.6.7.8'}, set(records[('www', 'A')].values)
        )

        # Verify AAAA
        self.assertIn(('ipv6', 'AAAA'), records)
        self.assertIn('2001:db8::1', records[('ipv6', 'AAAA')].values)

        # Verify CNAME
        self.assertIn(('mail', 'CNAME'), records)
        self.assertEqual(f'www.{TEST_ZONE}', records[('mail', 'CNAME')].value)

        # Verify MX
        self.assertIn(('', 'MX'), records)
        mx_values = sorted(
            records[('', 'MX')].values, key=lambda v: v.preference
        )
        self.assertEqual(10, mx_values[0].preference)
        self.assertEqual(20, mx_values[1].preference)

        # Verify TXT
        self.assertIn(('txt', 'TXT'), records)
        self.assertEqual(
            {'v=spf1 ~all', 'some-other-txt'},
            set(records[('txt', 'TXT')].values),
        )

        # Verify SRV
        self.assertIn(('_sip._tcp', 'SRV'), records)
        self.assertEqual(10, records[('_sip._tcp', 'SRV')].values[0].priority)

        # Verify CAA
        self.assertIn(('', 'CAA'), records)
        self.assertEqual('issue', records[('', 'CAA')].values[0].tag)

        # Verify NAPTR
        self.assertIn(('naptr', 'NAPTR'), records)
        self.assertEqual(100, records[('naptr', 'NAPTR')].values[0].order)

        # 4. Update: change A record values
        desired2 = Zone(TEST_ZONE, [])
        # Copy all existing records but change www A
        for r in zone2.records:
            if r.name == 'www' and r._type == 'A':
                desired2.add_record(
                    Record.new(
                        desired2,
                        'www',
                        {
                            'type': 'A',
                            'ttl': 300,
                            'values': ['10.0.0.1', '10.0.0.2'],
                        },
                    )
                )
            else:
                desired2.add_record(
                    Record.new(desired2, r.name, {'type': r._type, **r.data})
                )

        plan2 = provider.plan(desired2)
        self.assertIsNotNone(plan2)
        # Should have exactly 1 update
        self.assertEqual(1, len(plan2.changes))
        provider.apply(plan2)

        # 5. Verify update took effect
        zone3 = Zone(TEST_ZONE, [])
        provider.populate(zone3)
        records3 = {(r.name, r._type): r for r in zone3.records}
        self.assertEqual(
            {'10.0.0.1', '10.0.0.2'}, set(records3[('www', 'A')].values)
        )

        # 6. Plan with no changes should return None
        desired3 = Zone(TEST_ZONE, [])
        for r in zone3.records:
            desired3.add_record(
                Record.new(desired3, r.name, {'type': r._type, **r.data})
            )
        plan3 = provider.plan(desired3)
        self.assertIsNone(plan3)

    def test_ds_sshfp_tlsa_records(self):
        """Test DS, SSHFP, and TLSA record types."""
        provider = self.provider

        # Create zone first
        provider._create_zone(self.zone_name)

        desired = Zone(TEST_ZONE, [])
        desired.add_record(
            Record.new(
                desired,
                '',
                {'type': 'NS', 'ttl': 3600, 'values': [f'ns1.{TEST_ZONE}']},
            )
        )
        desired.add_record(
            Record.new(
                desired,
                'sshfp',
                {
                    'type': 'SSHFP',
                    'ttl': 300,
                    'values': [
                        {
                            'algorithm': 1,
                            'fingerprint_type': 2,
                            'fingerprint': '123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
                        }
                    ],
                },
            )
        )
        desired.add_record(
            Record.new(
                desired,
                'ds',
                {
                    'type': 'DS',
                    'ttl': 300,
                    'values': [
                        {
                            'key_tag': 12345,
                            'algorithm': 8,
                            'digest_type': 2,
                            'digest': '49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE49FD46E6C4B45C55D4AC69CB',
                        }
                    ],
                },
            )
        )
        desired.add_record(
            Record.new(
                desired,
                '_443._tcp',
                {
                    'type': 'TLSA',
                    'ttl': 300,
                    'values': [
                        {
                            'certificate_usage': 3,
                            'selector': 1,
                            'matching_type': 1,
                            'certificate_association_data': 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
                        }
                    ],
                },
            )
        )

        plan = provider.plan(desired)
        self.assertIsNotNone(plan)
        provider.apply(plan)

        # Re-populate and verify
        zone2 = Zone(TEST_ZONE, [])
        provider.populate(zone2)
        records = {(r.name, r._type): r for r in zone2.records}

        # SSHFP
        self.assertIn(('sshfp', 'SSHFP'), records)
        sshfp = records[('sshfp', 'SSHFP')].values[0]
        self.assertEqual(1, sshfp.algorithm)
        self.assertEqual(2, sshfp.fingerprint_type)

        # DS
        self.assertIn(('ds', 'DS'), records)
        ds = records[('ds', 'DS')].values[0]
        self.assertEqual(12345, ds.key_tag)
        self.assertEqual(8, ds.algorithm)
        self.assertEqual(2, ds.digest_type)

        # TLSA
        self.assertIn(('_443._tcp', 'TLSA'), records)
        tlsa = records[('_443._tcp', 'TLSA')].values[0]
        self.assertEqual(3, tlsa.certificate_usage)
        self.assertEqual(1, tlsa.selector)
        self.assertEqual(1, tlsa.matching_type)

    def test_alias_aname_roundtrip(self):
        """Test ALIAS/ANAME bidirectional mapping against live server."""
        provider = self.provider

        provider._create_zone(self.zone_name)

        desired = Zone(TEST_ZONE, [])
        desired.add_record(
            Record.new(
                desired,
                '',
                {'type': 'NS', 'ttl': 3600, 'values': [f'ns1.{TEST_ZONE}']},
            )
        )
        desired.add_record(
            Record.new(
                desired,
                '',
                {'type': 'ALIAS', 'ttl': 300, 'value': f'www.{TEST_ZONE}'},
            )
        )

        plan = provider.plan(desired)
        self.assertIsNotNone(plan)
        provider.apply(plan)

        # Re-populate
        zone2 = Zone(TEST_ZONE, [])
        provider.populate(zone2)
        records = {(r.name, r._type): r for r in zone2.records}

        self.assertIn(('', 'ALIAS'), records)
        self.assertEqual(f'www.{TEST_ZONE}', records[('', 'ALIAS')].value)

    def test_dname_record(self):
        """Test DNAME record type."""
        provider = self.provider

        provider._create_zone(self.zone_name)

        desired = Zone(TEST_ZONE, [])
        desired.add_record(
            Record.new(
                desired,
                '',
                {'type': 'NS', 'ttl': 3600, 'values': [f'ns1.{TEST_ZONE}']},
            )
        )
        desired.add_record(
            Record.new(
                desired,
                'legacy',
                {'type': 'DNAME', 'ttl': 300, 'value': f'new.{TEST_ZONE}'},
            )
        )

        plan = provider.plan(desired)
        self.assertIsNotNone(plan)
        provider.apply(plan)

        zone2 = Zone(TEST_ZONE, [])
        provider.populate(zone2)
        records = {(r.name, r._type): r for r in zone2.records}

        self.assertIn(('legacy', 'DNAME'), records)
        self.assertEqual(f'new.{TEST_ZONE}', records[('legacy', 'DNAME')].value)
