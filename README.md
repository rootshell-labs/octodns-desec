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
```

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
