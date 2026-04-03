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

| Column            | Type     | Notes                          |
|-------------------|----------|--------------------------------|
| id                | TEXT PK  | UUID                           |
| domain            | TEXT     | UNIQUE, e.g. alice.example     |
| owner_token_hash  | TEXT     | argon2 hash                    |
| challenge_type    | TEXT     | dns-01 or http-01              |
| challenge_token   | TEXT     | nullable, pending challenge    |
| verified          | BOOL     |                                |
| created_at        | DATETIME |                                |
| verified_at       | DATETIME |                                |

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
| service_token_id | TEXT FK  | references service_tokens.id         |
| domain_id        | TEXT FK  | references domains.id                |
| resource_uri     | TEXT     | e.g. acct:alice@alice.example        |
| rel              | TEXT     |                                      |
| href             | TEXT     | nullable                             |
| type             | TEXT     | nullable, media type                 |
| titles           | TEXT     | nullable, JSON object                |
| properties       | TEXT     | nullable, JSON object                |
| template         | TEXT     | nullable, RFC 6570 URI template      |
| ttl_seconds      | INTEGER  | nullable, NULL means permanent       |
| created_at       | DATETIME |                                      |
| expires_at       | DATETIME | nullable, computed from ttl          |

### Relationships

- domains 1:N service_tokens
- domains 1:N links
- service_tokens 1:N links

### Key Decisions

- **resource_pattern** uses glob matching. `acct:*@alice.example` means any user at the
  domain. Domain owners can restrict further, e.g. `acct:blog-*@alice.example`.
- **allowed_rels** is a JSON array. On registration, webfingerd validates the incoming
  link's rel is in this list.
- **links** stores individual link objects, not full JRD responses. At query time,
  webfingerd assembles the JRD from all links matching the resource (and optional rel
  filter).
- **ttl_seconds** nullable. NULL means permanent. When set, expires_at is computed as
  created_at + ttl_seconds. The reaper cleans expired entries.
- Token hashes use argon2. Plaintext tokens are never stored.

## Authorization Flow

### Phase 1: Domain Onboarding (self-service)

1. Domain owner calls `POST /api/v1/domains` with their domain name and preferred
   challenge type (dns-01 or http-01).
2. webfingerd generates a challenge token and returns instructions:
   - **dns-01**: create a TXT record at `_webfinger-challenge.{domain}` with the token
   - **http-01**: serve the token at `https://{domain}/.well-known/webfinger-verify/{token}`
3. Domain owner provisions the challenge.
4. Domain owner calls `POST /api/v1/domains/{id}/verify`.
5. webfingerd verifies the challenge (DNS lookup or HTTP GET).
6. On success, returns a domain owner token. This token is shown once and stored only
   as an argon2 hash.

Challenge tokens expire after a configurable TTL (default 1 hour).

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

A `DashMap<String, Vec<Link>>` keyed by `resource_uri`. DashMap provides concurrent
lock-free reads suitable for the high-read, low-write webfinger query pattern.

### Cache Operations

- **Startup hydration**: load all non-expired links from SQLite, group by resource_uri,
  populate the DashMap.
- **Write-through**: API writes go to SQLite first, then insert/update the affected
  resource's entry in the cache.
- **TTL reaper**: background tokio task runs every ~30 seconds, queries for
  `expires_at < now()`, deletes from SQLite, evicts from cache.

### Query Path

1. Parse `resource` and optional `rel` parameters from the request.
2. Look up `resource_uri` in the DashMap. Return 404 if not found.
3. If `rel` parameters are present, filter the Vec<Link> to matching rels.
4. Assemble JRD response (subject, aliases, links array).
5. Return `application/jrd+json` with CORS headers (`Access-Control-Allow-Origin: *`).

### host-meta

`GET /.well-known/host-meta` returns a static XRD document containing an LRDD template
pointing to the webfinger endpoint. No cache interaction needed.

## REST API

### Domain Onboarding

| Method | Path                          | Auth         | Description                |
|--------|-------------------------------|--------------|----------------------------|
| POST   | /api/v1/domains               | none         | Register domain, get challenge |
| GET    | /api/v1/domains/{id}          | owner_token  | Get domain status          |
| POST   | /api/v1/domains/{id}/verify   | none         | Submit for verification    |
| DELETE | /api/v1/domains/{id}          | owner_token  | Remove domain + all links  |

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
| GET    | /metrics  | none | Prometheus metrics |
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
session_secret = "override-via-env"
```

## Deployment

- Single static binary (musl target for portability)
- SQLite file on a persistent volume
- Reverse proxy (nginx/caddy) terminates TLS and forwards to webfingerd
- User points their domain's DNS to the reverse proxy (A/CNAME record)
- Multiple domains can point to the same instance. webfingerd resolves the correct
  links based on the resource parameter, not the Host header.

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
