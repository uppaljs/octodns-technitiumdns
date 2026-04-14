## octodns-technitiumdns - Technitium DNS provider for octodns

An [octodns](https://github.com/octodns/octodns/) provider that targets [Technitium DNS Server](https://technitium.com/dns/).

### Installation

```
pip install octodns-technitiumdns
```

### Configuration

```yaml
providers:
  technitium:
    class: octodns_technitiumdns.TechnitiumDnsProvider
    host: dns.example.com
    token: env/TECHNITIUM_API_TOKEN
    # port: 5380          # optional, default 5380
    # scheme: http        # optional, default http
    # timeout: 30         # optional, default 30 seconds
```

### Supported Record Types

A, AAAA, ALIAS (ANAME), CAA, CNAME, DNAME, DS, LOC, MX, NAPTR, NS, PTR, SSHFP, SRV, TLSA, TXT

### Usage

```yaml
zones:
  example.com.:
    sources:
      - config
    targets:
      - technitium
```

### Development

```
python -m venv env
source env/bin/activate
pip install -e ".[dev]"
pytest
```
