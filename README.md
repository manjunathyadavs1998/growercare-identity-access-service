# growercare-identity-access-service

Users, partner organisations, role grants with geographic/BU scope, and the **effective principal** that every other
GrowerCare service asks for (`/internal/users/{sub}/principal`). Publishes `iam.grant.created` / `iam.grant.revoked`
through the transactional outbox (Debezium → Kafka). Port **8081**.

It depends on other services only over the network:
- **Keycloak** proves identity.
- **PostgreSQL** `gc_iam` is its own database.
- **Kafka** receives events through the outbox.

## Run locally
1. Start [growercare-local-platform](https://github.com/manjunathyadavs1998/growercare-local-platform): `docker compose up -d --wait`.
2. Configure and run:
   ```bash
   cp .env.example .env                                   # every variable, documented (dev-only values)
   mvn -B package jib:dockerBuild -DskipTests             # image ghcr.io/manjunathyadavs1998/identity-access-service
   docker compose up -d                                   # joins the "growercare" network
   ```
   Swagger UI: http://localhost:8081/swagger-ui/index.html (only with `GC_API_DOCS_ENABLED=true`).

**Configuration comes only from environment variables** (ADR-017, SPEC-PLAT-06):
- No URL, host, user, password or secret has a default.
- With variables missing, the service refuses to start and names them all.
- In AWS the values come from Secrets Manager via External Secrets.

## Build and test
```bash
mvn -B verify      # unit + Testcontainers integration tests, ArchUnit, OpenAPI contract (contracts/), coverage >= 80 %
```
The platform libraries (`gc-parent` 1.0.0, …) come from GitHub Packages:
- **CI:** uses `GITHUB_TOKEN`.
- **Locally, either:**
  - add a PAT with `read:packages` to `~/.m2/settings.xml` (server id `github`); or
  - `mvn install -Drevision=1.0.0` in growercare-platform-libs at tag `v1.0.0`.

## Specs
- `docs/specs/iam/`: this service's behaviour.
- `docs/schema.md`: the database schema.
- Cross-cutting specs and ADRs: [growercare](https://github.com/manjunathyadavs1998/growercare).
