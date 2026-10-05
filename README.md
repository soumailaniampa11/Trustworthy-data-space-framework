# Trustworthy Data Space Framework

Research prototype of a sovereign data space (in the spirit of IDS / Gaia-X):
participants keep their data in their own connector, publish offers in a shared
catalog, and govern their use with machine-readable policies that are enforced
continuously and recorded in a tamper-evident audit log.

## Trust mechanisms

| Concern | Mechanism | Module |
|---|---|---|
| Identity | Ed25519 keys, challenge-response login, authority-signed session tokens | `dataspace.identity` |
| Sovereignty | Data stays in the provider's connector; the catalog only holds offers | `dataspace.exchange`, `dataspace.catalog` |
| Usage control | ODRL-inspired policies (permissions, prohibitions, constraints, duties), deny-by-default, prohibition-overrides | `dataspace.policy` |
| Enforcement | Policy re-evaluated at every use of a grant (revocation, expiry, usage limits, policy or attribute changes take effect immediately) | `dataspace.access` |
| Integrity & provenance | SHA-256 checksum in the catalog + provider-signed payloads, verified by the consumer connector | `dataspace.exchange` |
| Accountability | Hash-chained audit log; any modification is detected by `verify()` | `dataspace.audit` |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

pytest                                  # run the test suite
python scripts/seed_data.py             # demo with participants A, B, C

DATASPACE_PARTICIPANTS_DIR=participants PYTHONPATH=src uvicorn api.main:app --reload
# -> http://localhost:8000/docs
```

## Python usage

```python
from dataspace import DataSpace
from dataspace.catalog import DatasetMetadata
from dataspace.policy import Constraint, Rule

space = DataSpace()
space.join("hospital", "Hospital", "Hospital", ["provider"], {"country": "FR"})
space.join("lab", "Lab", "Lab", ["consumer"], {"country": "DE"})

space.publish_dataset("hospital", "records", b"...", DatasetMetadata(title="Records"), [
    Rule(actions=["read"], constraints=[
        Constraint(left_operand="purpose", operator="eq", right_operand="research")]),
])
request = space.request_access("lab", "records", "read", purpose="research")
process, data = space.transfer(request.grant_id, "lab")
space.audit.verify()
```

## Layout

```
src/dataspace/   core library (identity, catalog, policy, access, exchange, audit, space.py facade)
api/             FastAPI REST API
participants/    YAML configs and sample data of participants A (hospital, FR),
                 B (research institute, DE) and C (company, US)
tests/           unit and integration tests
docs/            architecture, governance and research notes
experiments/     evaluation scenarios
```

All state is currently in memory. PostgreSQL, MinIO and Keycloak
(`infrastructure/`, `docker-compose.yml`) are planned as persistent back ends.
