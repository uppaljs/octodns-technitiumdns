from collections import defaultdict
from logging import getLogger

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

__VERSION__ = '1.0.0'


class TechnitiumDnsProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = True
    SUPPORTS_MULTIVALUE_PTR = True

    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'ALIAS',
            'CAA',
            'CNAME',
            'DNAME',
            'DS',
            'LOC',
            'MX',
            'NAPTR',
            'NS',
            'PTR',
            'SSHFP',
            'SRV',
            'TLSA',
            'TXT',
        )
    )

    # Conditionally add types that may not be available in all octodns versions
    try:
        from octodns.record.svcb import SvcbRecord  # noqa: F401

        SUPPORTS.add('SVCB')
        SUPPORTS.add('HTTPS')
    except ImportError:  # pragma: no cover
        pass
    try:
        from octodns.record.uri import UriRecord  # noqa: F401

        SUPPORTS.add('URI')
    except ImportError:  # pragma: no cover
        pass

    # Mapping from Technitium string enum values to integers for DS
    DS_ALGORITHM_MAP = {
        'RSAMD5': 1,
        'DH': 2,
        'DSA': 3,
        'RSASHA1': 5,
        'DSA-NSEC3-SHA1': 6,
        'RSASHA1-NSEC3-SHA1': 7,
        'RSASHA256': 8,
        'RSASHA512': 10,
        'ECC-GOST': 12,
        'ECDSAP256SHA256': 13,
        'ECDSAP384SHA384': 14,
        'ED25519': 15,
        'ED448': 16,
    }
    DS_DIGEST_TYPE_MAP = {
        'SHA1': 1,
        'SHA-1': 1,
        'SHA256': 2,
        'SHA-256': 2,
        'GOST': 3,
        'SHA384': 4,
        'SHA-384': 4,
    }

    # SSHFP mappings
    SSHFP_ALGORITHM_MAP = {
        'RSA': 1,
        'DSA': 2,
        'ECDSA': 3,
        'Ed25519': 4,
        'ED25519': 4,
        'Ed448': 6,
        'ED448': 6,
    }
    SSHFP_FINGERPRINT_TYPE_MAP = {
        'SHA-1': 1,
        'SHA1': 1,
        'SHA-256': 2,
        'SHA256': 2,
    }

    # TLSA mappings
    TLSA_CERTIFICATE_USAGE_MAP = {
        'PKIX-TA': 0,
        'PKIX-EE': 1,
        'DANE-TA': 2,
        'DANE-EE': 3,
    }
    TLSA_SELECTOR_MAP = {'Cert': 0, 'Full': 0, 'SPKI': 1}
    TLSA_MATCHING_TYPE_MAP = {
        'Full': 0,
        'SHA2-256': 1,
        'SHA-256': 1,
        'SHA2-512': 2,
        'SHA-512': 2,
    }

    def __init__(
        self,
        id,
        host,
        token,
        port=5380,
        scheme='http',
        timeout=30,
        *args,
        **kwargs,
    ):
        self.log = getLogger(f'TechnitiumDnsProvider[{id}]')
        self.log.debug(
            '__init__: id=%s, host=%s, port=%d, scheme=%s',
            id,
            host,
            port,
            scheme,
        )
        super().__init__(id, *args, **kwargs)

        self._host = host
        self._port = port
        self._scheme = scheme
        self._token = token
        self._timeout = timeout

        self._base_url = f'{scheme}://{host}:{port}'

        sess = Session()
        sess.headers.update(
            {
                'User-Agent': f'octodns/{octodns_version} octodns-technitiumdns/{__VERSION__}'
            }
        )
        self._sess = sess

    def _request(self, method, path, data=None):
        self.log.debug('_request: method=%s, path=%s', method, path)

        url = f'{self._base_url}/{path}'

        if data is None:
            data = {}

        # Token is always passed as a query parameter
        params = {'token': self._token}

        if method == 'GET':
            params.update(data)
            resp = self._sess.get(url, params=params, timeout=self._timeout)
        else:
            resp = self._sess.post(
                url, params=params, data=data, timeout=self._timeout
            )

        resp.raise_for_status()
        result = resp.json()

        if result.get('status') != 'ok':
            error_msg = result.get('errorMessage', 'Unknown error')
            raise ProviderException(f'Technitium API error: {error_msg}')

        return result

    def _get(self, path, params=None):
        return self._request('GET', path, data=params)

    def _post(self, path, data=None):
        return self._request('POST', path, data=data)

    def _zone_name(self, zone):
        """Convert octodns zone name (with trailing dot) to Technitium
        zone name (without trailing dot)."""
        return zone.name[:-1]

    def _zone_exists(self, zone_name):
        """Check if a zone exists in Technitium."""
        result = self._get('api/zones/list')
        zones = result.get('response', {}).get('zones', [])
        for z in zones:
            if z.get('name') == zone_name:
                return True
        return False

    def _create_zone(self, zone_name):
        """Create a primary zone in Technitium and clean up the
        auto-created default NS record."""
        self.log.debug('_create_zone: zone_name=%s', zone_name)
        self._post('api/zones/create', {'domain': zone_name, 'type': 'Primary'})

        # Technitium auto-creates a default NS record with the server's
        # hostname (e.g. "ndns01"). This is not a valid FQDN and will
        # cause octodns validation errors. Delete all default NS records.
        try:
            result = self._get(
                'api/zones/records/get',
                {'domain': zone_name, 'zone': zone_name, 'type': 'NS'},
            )
            for record in result.get('response', {}).get('records', []):
                if record['type'] == 'NS':
                    self._post(
                        'api/zones/records/delete',
                        {
                            'domain': zone_name,
                            'zone': zone_name,
                            'type': 'NS',
                            'nameServer': record['rData']['nameServer'],
                        },
                    )
        except Exception:
            # Non-critical - the NS records will be managed by octodns
            pass

    @staticmethod
    def _ensure_trailing_dot(value):
        """Ensure a hostname/FQDN value has a trailing dot."""
        if value and not value.endswith('.'):
            return f'{value}.'
        return value

    @staticmethod
    def _to_int(value, mapping=None):
        """Convert a value to int, using a mapping if it's a string name."""
        if isinstance(value, int):
            return value
        if mapping and isinstance(value, str):
            mapped = mapping.get(value)
            if mapped is not None:
                return mapped
        try:
            return int(value)
        except (ValueError, TypeError):
            return value

    def _fqdn_for(self, record, zone_name):
        """Convert octodns record name to Technitium FQDN (no trailing dot)."""
        if record.name == '':
            return zone_name
        return f'{record.name}.{zone_name}'

    def _record_name(self, fqdn, zone_name):
        """Convert Technitium FQDN to octodns relative record name."""
        if fqdn == zone_name:
            return ''
        suffix = f'.{zone_name}'
        if fqdn.endswith(suffix):
            return fqdn[: -len(suffix)]
        return fqdn

    # ---------------------------------------------------------------
    # _data_for_* methods: Technitium rData -> octodns record data
    # ---------------------------------------------------------------

    def _data_for_A(self, rrdata):
        return {
            'type': 'A',
            'ttl': rrdata['ttl'],
            'values': [r['rData']['ipAddress'] for r in rrdata['records']],
        }

    def _data_for_AAAA(self, rrdata):
        return {
            'type': 'AAAA',
            'ttl': rrdata['ttl'],
            'values': [r['rData']['ipAddress'] for r in rrdata['records']],
        }

    def _data_for_CAA(self, rrdata):
        return {
            'type': 'CAA',
            'ttl': rrdata['ttl'],
            'values': [
                {
                    'flags': r['rData']['flags'],
                    'tag': r['rData']['tag'],
                    'value': r['rData']['value'],
                }
                for r in rrdata['records']
            ],
        }

    def _data_for_CNAME(self, rrdata):
        return {
            'type': 'CNAME',
            'ttl': rrdata['ttl'],
            'value': self._ensure_trailing_dot(
                rrdata['records'][0]['rData']['cname']
            ),
        }

    def _data_for_ALIAS(self, rrdata):
        return {
            'type': 'ALIAS',
            'ttl': rrdata['ttl'],
            'value': self._ensure_trailing_dot(
                rrdata['records'][0]['rData']['aname']
            ),
        }

    def _data_for_DNAME(self, rrdata):
        return {
            'type': 'DNAME',
            'ttl': rrdata['ttl'],
            'value': self._ensure_trailing_dot(
                rrdata['records'][0]['rData']['dname']
            ),
        }

    def _data_for_DS(self, rrdata):
        return {
            'type': 'DS',
            'ttl': rrdata['ttl'],
            'values': [
                {
                    'key_tag': int(r['rData']['keyTag']),
                    'algorithm': self._to_int(
                        r['rData'].get(
                            'algorithmNumber', r['rData']['algorithm']
                        ),
                        self.DS_ALGORITHM_MAP,
                    ),
                    'digest_type': self._to_int(
                        r['rData'].get(
                            'digestTypeNumber', r['rData']['digestType']
                        ),
                        self.DS_DIGEST_TYPE_MAP,
                    ),
                    'digest': r['rData']['digest'].upper(),
                }
                for r in rrdata['records']
            ],
        }

    def _data_for_LOC(self, rrdata):
        values = []
        for r in rrdata['records']:
            rd = r['rData']
            values.append(
                {
                    'lat_degrees': rd.get('latDegrees', rd.get('latitude', 0)),
                    'lat_minutes': rd.get('latMinutes', 0),
                    'lat_seconds': float(rd.get('latSeconds', 0.0)),
                    'lat_direction': rd.get('latDirection', 'N'),
                    'long_degrees': rd.get(
                        'longDegrees', rd.get('longitude', 0)
                    ),
                    'long_minutes': rd.get('longMinutes', 0),
                    'long_seconds': float(rd.get('longSeconds', 0.0)),
                    'long_direction': rd.get('longDirection', 'E'),
                    'altitude': float(rd.get('altitude', 0.0)),
                    'size': float(rd.get('size', 1.0)),
                    'precision_horz': float(
                        rd.get(
                            'horizontalPrecision',
                            rd.get('precisionHorz', 10000.0),
                        )
                    ),
                    'precision_vert': float(
                        rd.get(
                            'verticalPrecision', rd.get('precisionVert', 10.0)
                        )
                    ),
                }
            )
        return {'type': 'LOC', 'ttl': rrdata['ttl'], 'values': values}

    def _data_for_MX(self, rrdata):
        return {
            'type': 'MX',
            'ttl': rrdata['ttl'],
            'values': [
                {
                    'preference': r['rData']['preference'],
                    'exchange': self._ensure_trailing_dot(
                        r['rData']['exchange']
                    ),
                }
                for r in rrdata['records']
            ],
        }

    def _data_for_NAPTR(self, rrdata):
        return {
            'type': 'NAPTR',
            'ttl': rrdata['ttl'],
            'values': [
                {
                    'order': r['rData']['order'],
                    'preference': r['rData']['preference'],
                    'flags': r['rData']['flags'],
                    'service': r['rData']['services'],
                    'regexp': r['rData']['regexp'],
                    'replacement': self._ensure_trailing_dot(
                        r['rData']['replacement']
                    ),
                }
                for r in rrdata['records']
            ],
        }

    def _data_for_NS(self, rrdata):
        return {
            'type': 'NS',
            'ttl': rrdata['ttl'],
            'values': [
                self._ensure_trailing_dot(r['rData']['nameServer'])
                for r in rrdata['records']
            ],
        }

    def _data_for_PTR(self, rrdata):
        return {
            'type': 'PTR',
            'ttl': rrdata['ttl'],
            'values': [
                self._ensure_trailing_dot(r['rData']['ptrName'])
                for r in rrdata['records']
            ],
        }

    def _data_for_SSHFP(self, rrdata):
        return {
            'type': 'SSHFP',
            'ttl': rrdata['ttl'],
            'values': [
                {
                    'algorithm': self._to_int(
                        r['rData']['algorithm'], self.SSHFP_ALGORITHM_MAP
                    ),
                    'fingerprint_type': self._to_int(
                        r['rData']['fingerprintType'],
                        self.SSHFP_FINGERPRINT_TYPE_MAP,
                    ),
                    'fingerprint': r['rData']['fingerprint'].lower(),
                }
                for r in rrdata['records']
            ],
        }

    def _data_for_SRV(self, rrdata):
        return {
            'type': 'SRV',
            'ttl': rrdata['ttl'],
            'values': [
                {
                    'priority': r['rData']['priority'],
                    'weight': r['rData']['weight'],
                    'port': r['rData']['port'],
                    'target': self._ensure_trailing_dot(r['rData']['target']),
                }
                for r in rrdata['records']
            ],
        }

    def _data_for_TLSA(self, rrdata):
        return {
            'type': 'TLSA',
            'ttl': rrdata['ttl'],
            'values': [
                {
                    'certificate_usage': self._to_int(
                        r['rData']['certificateUsage'],
                        self.TLSA_CERTIFICATE_USAGE_MAP,
                    ),
                    'selector': self._to_int(
                        r['rData']['selector'], self.TLSA_SELECTOR_MAP
                    ),
                    'matching_type': self._to_int(
                        r['rData']['matchingType'], self.TLSA_MATCHING_TYPE_MAP
                    ),
                    'certificate_association_data': r['rData'][
                        'certificateAssociationData'
                    ].lower(),
                }
                for r in rrdata['records']
            ],
        }

    def _data_for_TXT(self, rrdata):
        return {
            'type': 'TXT',
            'ttl': rrdata['ttl'],
            'values': [r['rData']['text'] for r in rrdata['records']],
        }

    def _data_for_URI(self, rrdata):
        return {
            'type': 'URI',
            'ttl': rrdata['ttl'],
            'values': [
                {
                    'priority': r['rData']['priority'],
                    'weight': r['rData']['weight'],
                    'target': r['rData']['uri'],
                }
                for r in rrdata['records']
            ],
        }

    # ---------------------------------------------------------------
    # _params_for_* methods: octodns record -> Technitium API params
    # Returns a list of dicts, one per record value.
    # ---------------------------------------------------------------

    def _params_for_A(self, record):
        return [{'ipAddress': v} for v in record.values]

    _params_for_AAAA = _params_for_A

    def _params_for_CAA(self, record):
        return [
            {'flags': v.flags, 'tag': v.tag, 'value': v.value}
            for v in record.values
        ]

    def _params_for_CNAME(self, record):
        return [{'cname': record.value}]

    def _params_for_ALIAS(self, record):
        return [{'aname': record.value}]

    def _params_for_DNAME(self, record):
        return [{'dname': record.value}]

    def _params_for_DS(self, record):
        return [
            {
                'keyTag': v.key_tag,
                'algorithm': v.algorithm,
                'digestType': v.digest_type,
                'digest': v.digest,
            }
            for v in record.values
        ]

    def _params_for_LOC(self, record):
        params = []
        for v in record.values:
            params.append(
                {
                    'latDegrees': v.lat_degrees,
                    'latMinutes': v.lat_minutes,
                    'latSeconds': v.lat_seconds,
                    'latDirection': v.lat_direction,
                    'longDegrees': v.long_degrees,
                    'longMinutes': v.long_minutes,
                    'longSeconds': v.long_seconds,
                    'longDirection': v.long_direction,
                    'altitude': v.altitude,
                    'size': v.size,
                    'horizontalPrecision': v.precision_horz,
                    'verticalPrecision': v.precision_vert,
                }
            )
        return params

    def _params_for_MX(self, record):
        return [
            {'exchange': v.exchange, 'preference': v.preference}
            for v in record.values
        ]

    def _params_for_NAPTR(self, record):
        return [
            {
                'naptrOrder': v.order,
                'naptrPreference': v.preference,
                'naptrFlags': v.flags,
                'naptrServices': v.service,
                'naptrRegexp': v.regexp,
                'naptrReplacement': v.replacement,
            }
            for v in record.values
        ]

    def _params_for_NS(self, record):
        return [{'nameServer': v} for v in record.values]

    def _params_for_PTR(self, record):
        return [{'ptrName': v} for v in record.values]

    def _params_for_SSHFP(self, record):
        return [
            {
                'sshfpAlgorithm': v.algorithm,
                'sshfpFingerprintType': v.fingerprint_type,
                'sshfpFingerprint': v.fingerprint,
            }
            for v in record.values
        ]

    def _params_for_SRV(self, record):
        return [
            {
                'priority': v.priority,
                'weight': v.weight,
                'port': v.port,
                'target': v.target,
            }
            for v in record.values
        ]

    def _params_for_TLSA(self, record):
        return [
            {
                'tlsaCertificateUsage': v.certificate_usage,
                'tlsaSelector': v.selector,
                'tlsaMatchingType': v.matching_type,
                'tlsaCertificateAssociationData': v.certificate_association_data,
            }
            for v in record.values
        ]

    def _params_for_TXT(self, record):
        return [{'text': v} for v in record.values]

    def _params_for_URI(self, record):
        return [
            {'priority': v.priority, 'weight': v.weight, 'uri': v.target}
            for v in record.values
        ]

    # ---------------------------------------------------------------
    # Technitium record type name <-> octodns record type name
    # ---------------------------------------------------------------

    # Technitium type -> octodns type
    _TYPE_TO_OCTODNS = {'ANAME': 'ALIAS'}

    # octodns type -> Technitium type
    _TYPE_TO_TECHNITIUM = {'ALIAS': 'ANAME'}

    # ---------------------------------------------------------------
    # populate / _apply
    # ---------------------------------------------------------------

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        zone_name = self._zone_name(zone)

        exists = self._zone_exists(zone_name)
        if not exists:
            return False

        result = self._get(
            'api/zones/records/get',
            {'domain': zone_name, 'zone': zone_name, 'listZone': 'true'},
        )

        records = result.get('response', {}).get('records', [])

        # Group records by (relative_name, octodns_type)
        grouped = defaultdict(
            lambda: {'type': None, 'ttl': None, 'records': []}
        )
        for record in records:
            rtype = record['type']

            # Skip SOA records - octodns doesn't manage SOA
            if rtype == 'SOA':
                continue

            # Map Technitium-specific types to octodns types
            octodns_type = self._TYPE_TO_OCTODNS.get(rtype, rtype)

            if octodns_type not in self.SUPPORTS:
                continue

            # Skip disabled records
            if record.get('disabled', False):
                continue

            fqdn = record['name']
            relative_name = self._record_name(fqdn, zone_name)

            key = (relative_name, octodns_type)
            grouped[key]['type'] = octodns_type
            grouped[key]['ttl'] = record['ttl']
            grouped[key]['records'].append(record)

        # Convert grouped records to octodns Record objects
        for (record_name, rtype), rrdata in grouped.items():
            data_for = getattr(self, f'_data_for_{rtype}')
            octodns_data = data_for(rrdata)

            record = Record.new(
                zone, record_name, octodns_data, source=self, lenient=lenient
            )
            zone.add_record(record, lenient=lenient)

        self.log.info('populate:   found %s records', len(zone.records))
        return exists

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        zone_name = self._zone_name(desired)

        if not self._zone_exists(zone_name):
            self.log.debug('_apply: creating zone %s', zone_name)
            self._create_zone(zone_name)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(zone_name, change)

    def _apply_Create(self, zone_name, change):
        new = change.new
        rtype = new._type
        api_type = self._TYPE_TO_TECHNITIUM.get(rtype, rtype)

        params_for = getattr(self, f'_params_for_{rtype}')
        for params in params_for(new):
            self._post(
                'api/zones/records/add',
                {
                    'domain': self._fqdn_for(new, zone_name),
                    'zone': zone_name,
                    'type': api_type,
                    'ttl': new.ttl,
                    **params,
                },
            )

    def _apply_Delete(self, zone_name, change):
        existing = change.existing
        rtype = existing._type
        api_type = self._TYPE_TO_TECHNITIUM.get(rtype, rtype)

        params_for = getattr(self, f'_params_for_{rtype}')
        for params in params_for(existing):
            self._post(
                'api/zones/records/delete',
                {
                    'domain': self._fqdn_for(existing, zone_name),
                    'zone': zone_name,
                    'type': api_type,
                    **params,
                },
            )

    def _apply_Update(self, zone_name, change):
        # Delete all old values then add all new values.
        # Simpler and more reliable than using the update endpoint,
        # which requires matching old/new parameter pairs.
        self._apply_Delete(zone_name, change)
        self._apply_Create(zone_name, change)
