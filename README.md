# Homomorphic CKKS Floating Engine

**Important:** This repository currently contains a **rule-based threshold evaluation demonstration**, not an implementation of CKKS homomorphic encryption. It does **not** encrypt vectors, perform ciphertext arithmetic, validate homomorphic encryption standards, establish HIPAA compliance, or issue cryptographic security certifications.

## Features

- Three-worker Python evaluator: primary metrics (>25), secondary metrics (>12), critical flags, and anomaly keywords.
- CLI single-task evaluation, CSV batch processing, mock chat, and audit-trail verification.
- FastAPI server with /health, /metrics, /api/audit, /api/chat, and protected /api/audit/logs.
- In-memory HMAC-SHA256 chained audit records with signature recomputation; records are **not persisted**.
- A standalone, responsive browser interface at [web/index.html](web/index.html), with local JavaScript evaluation, opt-in API mode, and JSON export.
- A legacy evaluation interface in ckks_fhe_engine/ and eight enrichment modules. Despite their names, these modules use numerical thresholds and do not execute CKKS operations, side-channel proofs, or compliance tests.

## Browser use

Open [web/index.html](web/index.html) in a modern browser or use the GitHub Pages publication when enabled. Select **Local browser evaluation** and enter synthetic values. Local mode processes data entirely within the tab; choosing **Same-origin API** transmits it to your server. No Pyodide or server-side Python is required for the local browser mode.

The repository includes a GitHub Pages workflow to publish web/ from master. A live URL should only be advertised after its deployment is verified.

## Install and run

Requires Python 3.9 or newer.

~~~bash
python -m pip install -e ".[server,test]"
python -m pytest -q
homomorphic-ckks-floating-engine audit --task-id DEMO-001 --target SYNTHETIC-001 --primary 29.4 --secondary 14.8 --critical --status DISCORDANT
homomorphic-ckks-floating-engine batch -i sample.csv -o results.csv
homomorphic-ckks-floating-engine serve --host 127.0.0.1 --port 8000
~~~

Open http://127.0.0.1:8000/ for the form or http://127.0.0.1:8000/docs for the API documentation. The command **homomorphic-ckks-legacy** retains the earlier secondary CLI interface.

For a local container:

~~~bash
docker compose up --build
~~~

Compose binds the service to loopback on port 8000. Public production exposure requires authentication, TLS, rate limits, monitoring, and persistent audit storage.

## API example

~~~bash
curl -s http://127.0.0.1:8000/api/audit \
  -H 'Content-Type: application/json' \
  -d '{"task_id":"DEMO-001","target_identifier":"SYNTHETIC-001","primary_metric":29.4,"secondary_metric":14.8,"status_descriptor":"DISCORDANT","is_critical_flag":true}'
~~~

GET /api/audit/logs is disabled unless the server has the **AUDIT_API_TOKEN** environment variable set. Authorized clients supply the key in the **X-Audit-Token** header. **AUDIT_SECRET_KEY** configures the signing key; if unset, an ephemeral key is generated. The ledger itself is in memory and is lost on restart even with a persistent key.

## Privacy, security and limitations

**Use synthetic or appropriately de-identified inputs only.** Sensitive-identifier detection is regex-based, incomplete, and not a substitute for validated de-identification or formal privacy safeguards. Audit and chat input paths are not protected by a general authentication middleware. Never expose the default API publicly or send actual patient identifiers.

The HMAC chain can detect alterations to signed fields while the secret key is uncompromised, but it is not immutable or persistent storage. An operator with signing-key access can rewrite the entire chain. The audit records contain a hash of selected details, not a complete original payload.

The mock chat adapter does not perform real LLM inference; the threshold rules are demonstration constants with no cryptographic, clinical or regulatory significance. The enrichment modules are illustrative numeric checks, not actual interoperability tests or security validations.

## Development

~~~bash
python -m pip install -e ".[server,test]"
python -m pip check
python -m pytest -q
python -m pip install build
python -m build
~~~

GitHub Actions tests Python 3.9–3.12, builds a package, and exercises both console entry points. The static browser view has no third-party JavaScript dependencies, browser storage, or mandatory server connection.

## License

[MIT](LICENSE).
