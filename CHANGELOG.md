## v1.0.0 - First Stable Release

- Initial implementation of octodns-technitiumdns provider
- Support for record types: A, AAAA, ALIAS/ANAME, CAA, CNAME, DNAME, DS, LOC, MX, NAPTR, NS, PTR, SSHFP, SRV, TLSA, TXT
- Conditional support for HTTPS, SVCB, URI (based on octodns version)
- Full CRUD operations via Technitium DNS HTTP API
- Auto-creation of zones when target zone doesn't exist
- ANAME <-> ALIAS bidirectional type mapping
- 100% test coverage
- Automated PyPI publishing via GitHub Actions trusted publishers
