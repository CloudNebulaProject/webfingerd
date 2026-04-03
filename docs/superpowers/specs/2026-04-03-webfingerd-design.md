# webfingerd Design Specification

**Date:** 2026-04-03
**Status:** Approved

## Overview

webfingerd is a multi-tenant WebFinger server (RFC 7033) that centralizes WebFinger
responses for multiple domains and services. Domain owners point their DNS to a
webfingerd instance, then their backend services (e.g. barycenter for OIDC, oxifed for
ActivityPub) register their links via a REST API. webfingerd responds to public
WebFinger queries by assembling JRD responses from all registered links for the
requested resource.

### Problem

Multiple services need WebFinger: barycenter needs it for OIDC issuer discovery, oxifed
needs it for ActivityPub actor discovery. Each domain can only have one
`/.well-known/webfinger` endpoint. Rather than embedding WebFinger in every service or
using a reverse proxy to stitch responses together, a dedicated server aggregates links
from all services under one endpoint.

### Goals

- Serve RFC 7033 compliant WebFinger and RFC 6415 host-meta responses
- Support multiple domains and users from a single instance
- Self-service domain onboarding with ACME-style ownership verification
- Scoped authorization preventing services from registering foreign links
- Fast query path via in-memory cache, durable storage via SQLite
- Operational readiness: metrics, health checks, rate limiting, web UI

## Architecture

Single axum binary with modular internal components:

- **WebFinger query handler** serves `/.well-known/webfinger` and `/.well-known/host-meta`
- **REST management API** handles domain onboarding, token management, and link registration
- **Auth middleware** validates tokens and enforces scope (allowed rels + resource patterns)
- **In-memory cache** (DashMap keyed by resource URI) for O(1) query lookups
- **Domain challenge engine** verifies domain ownership via DNS-01 or HTTP-01 challenges
- **TTL reaper** (background tokio task) expires stale links
- **SQLite via SeaORM** as the durable source of truth
- **Prometheus metrics** and health check endpoints
- **Server-rendered web UI** (askama templates) for domain owner management

The query path reads exclusively from the in-memory cache. The write path goes through
SQLite first, then updates the cache (write-through). On startup, all non-expired links
are loaded from SQLite into the cache.

## Data Model

### domains

| Column              | Type     | Notes                          |
|---------------------|----------|--------------------------------|
| id                  | TEXT PK  | UUID                           |
| domain              | TEXT     | UNIQUE, e.g. alice.example     |
| owner_token_hash    | TEXT     | argon2 hash                    |
| registration_secret | TEXT     | argon2 hash, for verify auth   |
| challenge_type      | TEXT     | dns-01 or http-01              |
| challenge_token     | TEXT     | nullable, pending challenge    |
| verified            | BOOL     |                                |
| created_at          | DATETIME |                                |
| verified_at         | DATETIME |                                |

### resources

| Column       | Type     | Notes                                        |
|--------------|----------|----------------------------------------------|
| id           | TEXT PK  | UUID                                         |
| domain_id    | TEXT FK  | references domains.id                        |
| resource_uri | TEXT     | UNIQUE, canonical URI e.g. acct:alice@domain |
| aliases      | TEXT     | nullable, JSON array of alternative URIs     |
| properties   | TEXT     | nullable, JSON object for resource-level metadata |
| created_at   | DATETIME |                                              |
| updated_at   | DATETIME |                                              |

### service_tokens

| Column           | Type     | Notes                                |
|------------------|----------|--------------------------------------|
| id               | TEXT PK  | UUID                                 |
| domain_id        | TEXT FK  | references domains.id                |
| name             | TEXT     | human label, e.g. oxifed             |
| token_hash       | TEXT     | argon2 hash                          |
| allowed_rels     | TEXT     | JSON array of rel strings            |
| resource_pattern | TEXT     | glob, e.g. acct:*@social.alice.example |
| created_at       | DATETIME |                                      |
| revoked_at       | DATETIME | nullable                             |

### links

| Column           | Type     | Notes                                |
|------------------|----------|--------------------------------------|
| id               | TEXT PK  | UUID                                 |
| resource_id      | TEXT FK  | references resources.id              |
| service_token_id | TEXT FK  | references service_tokens.id         |
| domain_id        | TEXT FK  | references domains.id                |
| rel              | TEXT     |                                      |
| href             | TEXT     | nullable                             |
| type             | TEXT     | nullable, media type                 |
| titles           | TEXT     | nullable, JSON object                |
| properties       | TEXT     | nullable, JSON object                |
| template         | TEXT     | nullable, RFC 6570 URI template      |
| ttl_seconds      | INTEGER  | nullable, NULL means permanent       |
| created_at       | DATETIME |                                      |
| expires_at       | DATETIME | nullable, computed from ttl          |

**Unique constraint:** `(resource_id, rel, href)` — prevents duplicate links. Writes
with a matching tuple perform an upsert (update existing link).

### Relationships

- domains 1:N resources
- domains 1:N service_tokens
- resources 1:N links
- service_tokens 1:N links

### Cascade Behavior

- **Deleting a domain** deletes all its resources, service tokens, and links. Cache
  entries for all affected resource URIs are evicted.
- **Revoking a service token** deletes all links associated with that token from both
  SQLite and the cache.
- **Orphaned resources** (resources with zero links remaining after deletion/expiry)
  are cleaned up by the TTL reaper and evicted from the cache.
- The `domain_id` FK on `links` is intentional denormalization for query performance
  (avoids joins on domain-scoped operations). Writes must enforce consistency with
  the resource's `domain_id`.

### Key Decisions

- **resources** table stores the JRD `subject` (as `resource_uri`) and `aliases` per
  resource. RFC 7033 requires `subject` in the response. Services create or reference
  a resource when registering links.
- **resource_pattern** uses glob matching via the `glob-match` crate. `*` matches any
  sequence of characters (including none). Patterns are validated at creation time:
  they must contain at least one `@` and a domain suffix matching the token's domain.
  Overly broad patterns like `*` are rejected.
- **allowed_rels** is a JSON array. On registration, webfingerd validates the incoming
  link's rel is in this list.
- **links** stores individual link objects, not full JRD responses. At query time,
  webfingerd assembles the JRD from the resource's subject/aliases plus all matching
  links (filtered by optional `rel` parameters).
- **ttl_seconds** nullable. NULL means permanent. When set, expires_at is computed as
  created_at + ttl_seconds. The reaper cleans expired entries.
- Token hashes use argon2. Plaintext tokens are never stored.
- **Domain re-verification** is not implemented in v1. Once verified, a domain stays
  verified. This is a known limitation. A future `reverify_interval` mechanism could
  periodically re-check DNS/HTTP challenges to detect domain ownership changes.

## Authorization Flow

### Phase 1: Domain Onboarding (self-service)

1. Domain owner calls `POST /api/v1/domains` with their domain name and preferred
   challenge type (dns-01 or http-01).
2. webfingerd generates a challenge token and a **registration secret**, returning both
   along with challenge instructions:
   - **dns-01**: create a TXT record at `_webfinger-challenge.{domain}` with the token
   - **http-01**: serve the token at `https://{domain}/.well-known/webfinger-verify/{token}`
   - The registration secret is stored as an argon2 hash. It is required to call the
     verify endpoint, preventing race conditions where an attacker who knows the domain
     ID could verify before the legitimate owner.
3. Domain owner provisions the challenge.
4. Domain owner calls `POST /api/v1/domains/{id}/verify` with the registration secret.
5. webfingerd verifies the challenge (DNS lookup or HTTP GET).
6. On success, returns a domain owner token. This token is shown once and stored only
   as an argon2 hash. The registration secret is invalidated.

Challenge tokens expire after a configurable TTL (default 1 hour).

### Owner Token Rotation

Domain owners can rotate their token via `POST /api/v1/domains/{id}/rotate-token`
(authenticated with the current owner token). This generates a new token, invalidates
the old hash, and returns the new token once.

### Phase 2: Service Token Creation

1. Domain owner calls `POST /api/v1/domains/{id}/tokens` (authenticated with owner
   token), specifying:
   - `name`: human label (e.g. "oxifed")
   - `allowed_rels`: list of rel types this service can register
   - `resource_pattern`: glob pattern restricting which resources this service can write
2. webfingerd creates the service token, returns it once, stores only the hash.

### Phase 3: Link Registration

1. Service calls `POST /api/v1/links` (authenticated with service token) with link
   data: resource_uri, rel, href, type, ttl, etc.
2. webfingerd validates:
   - The link's `rel` is in the token's `allowed_rels`
   - The link's `resource_uri` matches the token's `resource_pattern`
   - The token's domain is verified
3. On success, writes to SQLite and updates the in-memory cache.

### Scope Enforcement Rules

- A service token can only create/update/delete links where the rel is in allowed_rels
  AND the resource_uri matches the resource_pattern AND the domain is verified.
- A domain owner token can only manage service tokens for its own verified domain.
- Tokens are shown once at creation. Only the hash is stored.

## In-Memory Cache

### Structure

A `DashMap<String, CachedResource>` keyed by `resource_uri`, where `CachedResource`
contains the subject, aliases, and a `Vec<Link>`. DashMap provides concurrent lock-free
reads suitable for the high-read, low-write webfinger query pattern.

### Cache Operations

- **Startup hydration**: load all non-expired links from SQLite, group by resource_uri,
  populate the DashMap.
- **Write-through**: API writes go to SQLite first, then insert/update the affected
  resource's entry in the cache.
- **TTL reaper**: background tokio task runs every ~30 seconds, queries for
  `expires_at < now()`, deletes from SQLite, evicts from cache.

### Query Path

1. Parse `resource` and optional `rel` parameters from the request. Multiple `rel`
   parameters are supported per RFC 7033 Section 4.1.
2. Look up `resource_uri` in the DashMap. Return 404 if not found.
3. If `rel` parameters are present, filter links to those whose `rel` matches **any**
   of the provided values. All other JRD fields (subject, aliases, properties) are
   returned regardless of `rel` filtering.
4. Assemble JRD response from the cached resource's subject, aliases, and filtered links.
5. Return `application/jrd+json` with CORS headers (`Access-Control-Allow-Origin: *`).
   The management API does NOT send `Access-Control-Allow-Origin: *`.

### host-meta

`GET /.well-known/host-meta` returns an XRD (XML) document containing an LRDD template
pointing to the webfinger endpoint. The response inspects the `Host` header (or
`X-Forwarded-Host` behind a reverse proxy) and returns a domain-appropriate XRD. Returns
404 for unregistered or unverified hosts. Only `application/xrd+xml` is served; JSON
content negotiation is not supported for host-meta.

## REST API

### Domain Onboarding

| Method | Path                          | Auth         | Description                |
|--------|-------------------------------|--------------|----------------------------|
| POST   | /api/v1/domains                    | none              | Register domain, get challenge + registration secret |
| GET    | /api/v1/domains/{id}               | owner_token       | Get domain status          |
| POST   | /api/v1/domains/{id}/verify        | registration_secret | Submit for verification  |
| POST   | /api/v1/domains/{id}/rotate-token  | owner_token       | Rotate owner token         |
| DELETE | /api/v1/domains/{id}               | owner_token       | Remove domain + all tokens + all links |

### Service Tokens

| Method | Path                               | Auth         | Description         |
|--------|-------------------------------------|-------------|---------------------|
| POST   | /api/v1/domains/{id}/tokens         | owner_token | Create service token |
| GET    | /api/v1/domains/{id}/tokens         | owner_token | List service tokens  |
| DELETE | /api/v1/domains/{id}/tokens/{tid}   | owner_token | Revoke token         |

### Links

| Method | Path                    | Auth          | Description              |
|--------|-------------------------|---------------|--------------------------|
| POST   | /api/v1/links           | service_token | Register link(s)         |
| GET    | /api/v1/links?resource= | service_token | List links for resource  |
| PUT    | /api/v1/links/{lid}     | service_token | Update link              |
| DELETE | /api/v1/links/{lid}     | service_token | Delete link              |
| POST   | /api/v1/links/batch     | service_token | Bulk register/update     |

### Public Endpoints

| Method | Path                       | Auth | Description              |
|--------|----------------------------|------|--------------------------|
| GET    | /.well-known/webfinger     | none | RFC 7033 WebFinger query |
| GET    | /.well-known/host-meta     | none | RFC 6415 host-meta       |

### Operational

| Method | Path      | Auth | Description        |
|--------|-----------|------|--------------------|
| GET    | /metrics  | none | Prometheus metrics (restrict via network/firewall) |
| GET    | /healthz  | none | Health check       |

### Error Responses

All management endpoints return standard errors: 400 (bad request), 401 (invalid
token), 403 (scope violation), 404 (not found), 409 (conflict/duplicate), 429 (rate
limited with Retry-After header).

The public webfinger endpoint returns 404 for unknown resources per RFC 7033. It does
not reveal which resources exist vs which domains are registered.

### Batch Endpoint

`POST /api/v1/links/batch` accepts an array of link objects. Services like oxifed
registering many users at startup benefit from bulk registration rather than N individual
calls. Maximum 500 links per batch (configurable).

Batch uses **all-or-nothing transaction semantics**. If any link in the batch fails
validation, the entire batch is rejected and no links are written. The error response
includes the index and reason for each failing link.

## Web UI

A minimal server-rendered UI for domain owners to manage their domains and tokens.

### Pages

- **Login**: authenticate with owner token (paste token, receive session cookie)
- **Dashboard**: list verified domains, pending challenges, link counts per domain
- **Domain detail**: challenge instructions, verification status, service token list
- **Token management**: create/revoke service tokens, view allowed rels and resource patterns
- **Link browser**: read-only view of all links under a domain, filterable by resource/rel/service

### Implementation

- Server-side rendered with askama templates (compile-time type-safe, zero overhead)
- Minimal CSS, no JavaScript framework, progressive enhancement where needed
- Served under `/ui/*` from the same axum binary
- Session managed via signed cookies (axum-extra)
- Auth: owner token as credential, no separate username/password system

### Not in Scope

- No user registration/signup flow. Domain owners get their token from the API.
- No service link editing from the UI. Services manage their own links via API.
- No multi-user access per domain (one owner token per domain).

## Rate Limiting

Implemented as axum middleware using a token bucket algorithm (governor crate).

### Tiers

| Tier                 | Limit           | Scope    |
|----------------------|-----------------|----------|
| Public webfinger     | 60 req/min      | per IP   |
| Management API       | 300 req/min     | per token |
| Batch endpoint       | 10 req/min      | per token |

Returns 429 Too Many Requests with Retry-After header.

## Observability

### Prometheus Metrics

- `webfinger_queries_total{domain, status}` — query count by domain and HTTP status
- `webfinger_query_duration_seconds` — histogram of query latency
- `webfinger_links_total{domain}` — gauge of active links per domain
- `webfinger_domains_total{verified}` — gauge of registered domains
- `webfinger_cache_hits_total` / `webfinger_cache_misses_total`
- `webfinger_links_expired_total` — counter of TTL-reaped links
- `webfinger_challenge_verifications_total{type, result}` — DNS/HTTP challenge outcomes

### Health Check

- `GET /healthz` returns 200 if SQLite is reachable and cache is initialized.
- Returns 503 during startup hydration.

### Logging

- tracing crate with structured JSON output
- Request IDs propagated through all layers

## Configuration

Single TOML file with env var overrides (12-factor). Every key is overridable via env
using `__` as separator (e.g. `WEBFINGERD_SERVER__LISTEN`), powered by the config crate.

```toml
[server]
listen = "0.0.0.0:8080"
base_url = "https://webfinger.example.com"

[database]
path = "/var/lib/webfingerd/webfingerd.db"
# WAL mode is enabled by default for concurrent read performance
wal_mode = true

[cache]
reaper_interval_secs = 30

[rate_limit]
public_rpm = 60
api_rpm = 300
batch_rpm = 10
batch_max_links = 500

[challenge]
dns_txt_prefix = "_webfinger-challenge"
http_well_known_path = ".well-known/webfinger-verify"
challenge_ttl_secs = 3600

[ui]
enabled = true
# session_secret is REQUIRED with no default. Server refuses to start without it.
# Set via env: WEBFINGERD_UI__SESSION_SECRET
# session_secret = "your-secret-here"
```

## Deployment

- Single static binary (musl target for portability)
- SQLite file on a persistent volume
- Reverse proxy (nginx/caddy) terminates TLS and forwards to webfingerd
- User points their domain's DNS to the reverse proxy (A/CNAME record)
- Multiple domains can point to the same instance. webfingerd resolves the correct
  links based on the resource parameter, not the Host header.
- The `/metrics` endpoint should be restricted to internal networks via reverse proxy
  rules or firewall, as it exposes operational details (domain names, error rates).

## Crate Dependencies

| Crate                       | Purpose                           |
|-----------------------------|-----------------------------------|
| axum, tokio                 | HTTP server, async runtime        |
| sea-orm, sea-orm-migration  | ORM, database migrations          |
| dashmap                     | Concurrent in-memory cache        |
| governor                    | Rate limiting (token bucket)      |
| askama                      | Server-side HTML templates        |
| argon2                      | Token hashing                     |
| config, serde               | Configuration loading             |
| tracing, tracing-subscriber | Structured logging                |
| metrics, metrics-exporter-prometheus | Prometheus metrics export |
| hickory-resolver            | DNS challenge verification        |
| reqwest                     | HTTP challenge verification       |
| glob-match                  | Resource pattern matching         |
