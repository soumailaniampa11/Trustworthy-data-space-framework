# MinIO — data plane storage

Each connector stores dataset contents (and data it received) in its own
bucket (`connector-a`, `connector-b`, `connector-c`), created on first use.
Only the owning connector accesses its bucket; other participants obtain
data exclusively through a transfer backed by a signed agreement.

Console: http://localhost:9001 (development credentials in `docker-compose.yml`).

In a production data space each participant would run its own object
storage inside its own infrastructure; a shared MinIO instance with one
bucket per participant is a development simplification.
