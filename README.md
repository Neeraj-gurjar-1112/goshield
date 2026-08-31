# GoShield

URL security scanner in Go. Concurrent scanning, Redis cache, PostgreSQL persistence, Swagger docs, React dashboard.

```
React dashboard ──► Go API ──► scanner engine (pure, offline)
                      │
                      ├──► Redis     (cache, not a source of truth)
                      └──► PostgreSQL (scan history)
```

## What it does

GoShield takes a URL and returns a risk verdict — SAFE, SUSPICIOUS or BLOCKED — with a 0–100 score and the list of signals that produced it.

The scanner is **fully offline**: every verdict is derived from the URL string alone. The service never sends a request to the URL being scanned, which keeps scans in the single-digit millisecond range and rules out SSRF entirely. Verdicts are cached in Redis (keyed on a normalized form of the URL) and every scan is stored in PostgreSQL, so the dashboard can show history, filters and aggregate stats. Bulk requests fan out across a bounded worker pool instead of spawning a goroutine per URL.

The detection itself is heuristic by design — see [Accuracy, honestly](#accuracy-honestly).

## Endpoints

Base path: `/api/v1`. Full request/response schemas are in Swagger (`/swagger/index.html`).

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/metrics` | In-memory counters, Prometheus text format |
| POST | `/api/v1/scan` | Scan one URL |
| GET | `/api/v1/scans/{id}` | Fetch a stored scan |
| GET | `/api/v1/scans` | History with paging and filters |
| POST | `/api/v1/scans/bulk` | Scan up to 100 URLs through the worker pool |

Every non-2xx response uses one envelope:

```json
{ "error": { "code": "INVALID_URL", "message": "The provided URL is invalid" } }
```

Codes: `INVALID_URL`, `INVALID_REQUEST`, `SCAN_NOT_FOUND`, `RATE_LIMIT_EXCEEDED`, `INTERNAL_SERVER_ERROR`, `SERVICE_UNAVAILABLE`.

`GET /api/v1/scans` accepts `page`, `limit` (max 100), `risk_level`, `status`, `domain`, `from`, `to` (RFC3339). Bad parameters are rejected with `400 INVALID_REQUEST` rather than silently ignored.

In a bulk response, each entry is either a scan object or `{ "url": ..., "error": { ... } }`, in input order — one malformed URL does not fail the batch.

## How to run

```bash
cp .env.example .env          # optional: only needed to override host ports
docker compose up --build
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| API | http://localhost:8080/api/v1 |
| Swagger UI | http://localhost:8080/swagger/index.html |
| Metrics | http://localhost:8080/metrics |
| Health | http://localhost:8080/health |

Migrations run automatically: a one-shot `migrate` service applies `migrations/` and the API only starts after it exits cleanly.

If a port is already taken on your machine, override it in `.env` — `FRONTEND_PORT`, `BACKEND_PORT`, `POSTGRES_PORT`, `REDIS_PORT`. When you move the frontend off port 3000, add its origin to `CORS_ORIGINS` too.

### Demo flow

```bash
# safe
curl -X POST localhost:8080/api/v1/scan -H 'Content-Type: application/json' \
  -d '{"url":"https://google.com"}'

# risky: http + suspicious TLD + three keywords -> score 65, SUSPICIOUS
curl -X POST localhost:8080/api/v1/scan -H 'Content-Type: application/json' \
  -d '{"url":"http://free-money-login.xyz/verify"}'

# blocklisted: short-circuits to 100, BLOCKED
curl -X POST localhost:8080/api/v1/scan -H 'Content-Type: application/json' \
  -d '{"url":"https://phishing-test.example/login"}'

# same URL again -> "cached": true
curl -X POST localhost:8080/api/v1/scan -H 'Content-Type: application/json' \
  -d '{"url":"https://google.com"}'
```

### Local development

The API can run on the host against the containerised database and cache:

```bash
docker compose up -d postgres redis migrate

DATABASE_URL='postgres://goshield:goshield@localhost:5433/goshield?sslmode=disable' \
REDIS_URL='redis://localhost:6379' \
go run ./cmd/server
```

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

`make` targets live in the `Makefile`: `run`, `build`, `test`, `test-race`, `test-docker`, `lint`, `swagger`, `swagger-docker`, `migrate-up`, `migrate-down`.

### Tests

```bash
go test ./...                  # unit tests
make test-docker               # go test -race in a Linux container
```

`make test-docker` exists for two reasons: the race detector needs a C toolchain (absent on a stock Windows box), and Windows Smart App Control blocks some locally built, unsigned test binaries — the scanner package in particular, because its blocklist and keyword lists look like phishing tooling to the heuristic. Running the suite in `golang:1.25` sidesteps both.

CI (`.github/workflows/verify.yml`) runs `gofmt`, `go vet`, the full test suite and a `docker build` on every push.

## Scanner rules

Signals are additive and the total is capped at 100.

| Signal | Points |
|---|---|
| Plain HTTP | +15 |
| Raw IP host | +25 |
| Non-standard port | +15 |
| URL longer than 100 chars | +10 |
| Punycode label (`xn--`) | +25 |
| Suspicious TLD (`.xyz`, `.top`, `.tk`, …) | +20 |
| More than 3 dots in the host | +15 |
| Suspicious keyword (`login`, `verify`, `wallet`, …) | +10 each, capped at +30 |
| Blocklisted domain | score = 100, short-circuits every other signal |

| Score | Risk level | Status | `safe` |
|---|---|---|---|
| 0–20 | SAFE | SAFE | true |
| 21–50 | LOW | SAFE | true |
| 51–75 | MEDIUM | SUSPICIOUS | false |
| 76–100 | HIGH | BLOCKED | false |

URLs are normalized before scoring, caching and storage: lowercase scheme and host, default port stripped, a bare trailing slash stripped, query preserved. The cache key is `goshield:scan:` + `sha256(normalized_url)`, so `HTTPS://Example.com:443/login` and `https://example.com/login` share one entry.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | Environment label in logs |
| `APP_PORT` | `8080` | HTTP port |
| `DATABASE_URL` | local postgres | PostgreSQL DSN |
| `REDIS_URL` | `redis://localhost:6379` | Redis URL |
| `WORKER_COUNT` | `10` | Workers in the bulk pool |
| `QUEUE_SIZE` | `100` | Buffered job queue depth |
| `CACHE_TTL_SECONDS` | `3600` | Cache entry lifetime |
| `RATE_LIMIT` | `100` | Requests per window per IP (`0` disables) |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window |
| `CORS_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Origins allowed to call the API from a browser |

Config is parsed once at startup and fails fast on an unusable value; nothing else in the codebase reads the environment.

Frontend: `VITE_API_URL` (baked into the bundle at build time — the browser is what calls the API, not the container).

## Design decisions worth defending

- **Offline analysis.** No outbound requests to scanned URLs. Scans are fast, deterministic, and SSRF is impossible by construction.
- **Bounded worker pool over unbounded goroutines.** A 100-URL bulk request fans out across `WORKER_COUNT` workers on a buffered queue. Results are collected by index, so the response preserves input order regardless of completion order. Caller cancellation and shutdown both unwind cleanly.
- **Redis is a cache, not a source of truth.** Every cache error — miss, malformed entry, connection refused — is reported as a miss and logged at warn level. Stop Redis mid-demo and the API keeps answering.
- **Constructor injection everywhere.** No package-level dependencies, which is why the service, handler and middleware tests need neither a database nor a Redis.
- **Error envelope in one place.** Handlers and middleware (including panic recovery) render the same shape through one helper.
- **Rate limiting on the connection address.** `X-Forwarded-For` is deliberately ignored, because a client can forge it. Behind a trusted proxy this would need revisiting.

## Where Claude was right, and where I had to fix it

Claude got the architecture right on the first pass: the handler → service → repository layering, the bounded worker pool, the offline scanner as a pure package, and the single error envelope all survived to the final version. The test suite it wrote (83 test functions) also caught my own mistakes more than once while I was changing things.

Where I had to step in:

1. **CORS was missing entirely.** The generated plan had a browser dashboard on one origin and the API on another, but no CORS layer — the dashboard could not have worked. I found this when the browser blocked every request, and added the CORS middleware with origins from `CORS_ORIGINS`.
2. **The plan contradicted itself on scoring.** Its verify step expected `http://free-money-login.xyz/verify` to come out HIGH, but its own weights table adds up to 65 — MEDIUM. I had to decide which one was authoritative (the weights table) instead of letting the code silently satisfy neither.
3. **My environment broke assumptions the AI didn't know about.** Port 5432 was already taken by a local PostgreSQL, so compose publishes on 5433; and Windows Smart App Control kept blocking the unsigned test binaries Go builds, which is why `make test-docker` exists and `GOTMPDIR` points inside the repo.
4. **The long-URL rule measured the raw URL, not the normalized one** — two spellings of the same URL could score differently and disagree with the cache. Measuring after normalization fixed it.

The pattern I took away: the AI is strongest on structure and weakest on the seams — between containers, between origins, between the plan and its own examples. That is exactly where I now check first.

## The Go concept that confused me most

Channels — specifically who owns one and when it gets closed. Coming from NestJS, my mental model of concurrency was async/await on one event loop: nothing truly runs at the same time and nothing "leaks". In Go, the worker pool sends jobs into a buffered channel and ten goroutines consume it, and my first understanding was wrong in both directions: I thought a full buffer would drop jobs (it blocks the sender instead), and I did not see why closing a channel from the receiving side is a bug (a worker can close it while a handler is still sending, which panics).

The rule that finally made it click, reading `internal/worker/pool.go` and its tests: **only the sender closes a channel, and a `select` on `ctx.Done()` is how everyone else finds out the work is over.** Cancellation is not an exception that unwinds the stack like in TypeScript — it is a signal every goroutine has to check on purpose.

## What I understand now that I did not before

- **Errors are values, and that changes how you design.** `result, err :=` at every call felt like boilerplate on day one. Now I see the point: every failure path in this codebase is visible in the code — the cache treats a Redis failure as a miss *because a line says so*, not because an exception happened to be caught somewhere upstream.
- **Bounded concurrency is a design decision, not a default.** A goroutine per URL would also "work". The buffered channel of size `QUEUE_SIZE` consumed by `WORKER_COUNT` workers is what puts a ceiling on memory and database connections under a 100-URL bulk request — that is what makes throughput predictable, which is the entire reason to use Go here.
- **`context` is the backbone, not a parameter you copy around.** One request context threads from the HTTP handler through the service into the pool and every SQL query; cancel it and everything under it stops. Graceful shutdown is the same mechanism with a 10-second `WithTimeout`.
- **No DI framework means the wiring is a place you can read.** `cmd/server/main.go` builds every dependency by hand in order. In NestJS the container hides that graph; here, if the wiring is wrong, it does not compile.

## Deviations from `GOSHIELD_BUILD_PLAN.md`

Documented rather than silently absorbed:

1. **CORS middleware was added.** The plan has a browser dashboard on a different origin from the API but no CORS layer, so the dashboard could not have worked. Origins come from `CORS_ORIGINS`; unknown origins get no CORS headers.
2. **`http://free-money-login.xyz/verify` scores 65 (MEDIUM), not HIGH.** The plan's Phase 2 verify comment expects HIGH, but its own weights table gives 15 (HTTP) + 20 (TLD) + 30 (keyword cap) = 65. The weights table is treated as authoritative.
3. **The long-URL threshold is measured on the normalized URL**, so two spellings of the same URL always score identically — otherwise a cached entry could disagree with a fresh scan.
4. **A cache hit is recorded as its own scan row** (new id, `cached: true`). The `cached` column in the plan's schema only makes sense if cached responses are stored, and history then reflects every request served.
5. **Metrics semantics.** `goshield_scans_safe_total` counts `safe == true` (score ≤ 50) and `goshield_scans_blocked_total` counts `status == BLOCKED` (score ≥ 76). SUSPICIOUS scans fall in neither, so the two do not add up to `goshield_scans_total`.
6. **Bulk entries can carry a per-URL error object** instead of a scan, so one invalid URL does not fail a 100-URL batch.
7. **Migrations run as a one-shot compose service** (`migrate/migrate`) that the API waits on, instead of from inside the API process.
8. **`limit` above 100 is a 400**, not a silent clamp — the plan allowed either.
9. **PostgreSQL is published on host port 5433** (5432 was already taken by a local PostgreSQL install). Inside the compose network it is still 5432.
10. **React 19 and Tailwind 4** — the current defaults from `npm create vite`, rather than the plan's React 18. Same libraries, newer majors.
11. **The server binary doubles as its own container healthcheck** (`/server -healthcheck`), because the distroless runtime image has no shell or curl.

## Accuracy, honestly

The detection is heuristic by design. A legitimate `/login` path scores 10, and a well-run `.xyz` domain scores 20 — false positives are expected. A production system would layer in threat-intelligence feeds, domain reputation, certificate data and allowlists, and treat these string heuristics as one weak signal among many. This repository is a Go engineering showcase, not a security product.

## Layout

```text
goshield/
├── cmd/server/           # wiring, graceful shutdown, healthcheck mode
├── internal/
│   ├── config/           # env parsing, fail fast
│   ├── handler/          # HTTP handlers, error envelope, swagger annotations
│   ├── service/          # scan + bulk orchestration
│   ├── security/         # the scanner engine (pure, offline, table-driven tests)
│   ├── repository/       # pgxpool queries
│   ├── cache/            # Redis, degrades to misses
│   ├── worker/           # generic bounded pool
│   ├── middleware/       # request id, logging, recovery, rate limit, CORS
│   ├── metrics/          # atomic counters
│   └── model/            # domain types
├── migrations/           # plain SQL, golang-migrate
├── docs/                 # generated swagger spec
├── frontend/             # Vite + React + TS + Tailwind + Recharts
├── Dockerfile            # backend image (multi-stage, distroless)
└── docker-compose.yml
```
