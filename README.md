## deSEC.io provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [deSEC.io](https://desec.readthedocs.io/en/latest/dns/domains.html).

### Installation

#### Command line

```
pip install octodns-desec
```

### Configuration

```yaml
providers:
  desec:
    class: octodns_desec.DesecProvider
    # Your deSEC API token (required)
    token: env/DESEC_TOKEN
    # (optional) max retries of each API request
    retries: 5
    # (optional) timeout of each API request
    timeout: 30
    # (optional) initial exponential backoff of each API request in seconds
    backoff: 2
    # (optional) maximum wait before retrying an API request in seconds
    # should the deSEC API request a wait time (once throttled) greater than this, this provider will fail
    max_sleep: 600
```

### Maintainers
This project is build and maintained in our free time.
(We are no members, just users of deSEC.)
- [blackdotraven](https://github.com/blackdotraven)
- [tilcreator](https://github.com/TilCreator/)

### Support Information

#### Records

DesecProvider supports:

- A
- AAAA
- CAA
- CNAME
- DS
- MX
- NS
- PTR
- SRV
- TLSA
- TXT

#### unsupported Records

Records not supported by OctoDNS but by deSEC:

- HTTPS
- OPENPGPKEY
- SMIMEA

#### Dynamic

DesecProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
