# SPEC-IAM-03: Grower self-registration (first-login provisioning)
- **Requirements:** IAM-1 (grower sign-up), Phase 1 PRD journey **J1** and decision D1 (Keycloak login with phone as username), UI readiness before M4
- **Status:** Implemented
- **Owner:** identity-access-service; Keycloak realm in growercare-local-platform
- **IDs:** rules IAM-R60+, examples IAM-E60+ (SPEC-IAM-01 uses R1–R5x; IAM-02 is reserved for the user directory)

## 0. Decisions (to agree with this spec)
| # | Decision | Why |
|---|---|---|
| D1 | **Keycloak's own registration page creates the login.** Realm `growercare`: `registrationAllowed: true`; the username is the phone in E.164 (`+919876543210`), enforced by a user-profile validator; a password policy (8+ characters). No email needed | Standard, hosted, no custom login code (agreed: "Keycloak + IAM on first login") |
| D2 | **IAM creates the GrowerCare account on the first call.** Right after sign-up the grower app calls `POST /self-registration {countryCode, displayName}` with its token. IAM accepts that one route for a valid token whose subject has **no** IAM user yet (every other route still needs one) | Keycloak knows identities, IAM knows grants; nothing else may skip IAM |
| D3 | **Self-registration only ever creates a GROWER** with one `GROWER` grant (scope OWN) in the chosen country, granted by "system" with reason `self-registration`. Staff and partners are never self-provisioned (admins create them: IAM-02) | Least privilege: a public sign-up can never yield staff power |
| D4 | **The country must match the phone:** the username's calling code must be the country's (`ref` data `iam.country.calling_code`: IN +91, BR +55), and the country must be active | One account per country (data residency); no "Indian phone, Brazil account" |
| D5 | **IAM stores only the phone's last 4 digits** for self-registered users (no HMAC: that key lives in grower-service). The phone of record stays in grower-service (SPEC-GRW-01 D3) | No second copy of a phone key |
| D6 | **Idempotent:** a subject already provisioned gets 200 with its `/me` view; the same subject asking for another country is 409 | Apps retry; the country is fixed once chosen |
| D7 | **Immediately usable everywhere:** principal caches never keep an "unknown subject" answer, so the new user works in every service at once | A grower should not wait 5 minutes after signing up |

## 1. Behaviour (rules)
| Rule | Given | When | Then |
|---|---|---|---|
| IAM-R60 | valid `gc-api` token, subject unknown to IAM, username `+91…` | `POST /self-registration {countryCode: "IN", displayName}` | 201 `/me` view: user GROWER, home country IN, one GROWER grant (OWN, IN); outbox `iam.grant.created`; audit row `user.self-register` |
| IAM-R61 | subject already provisioned (same country) · other country | same | 200 the existing `/me` · 409 `DUPLICATE` ("already registered in IN") |
| IAM-R62 | calling code of the username ≠ country's · inactive or unknown country · username not E.164 | register | 422 `iam.phone-country-mismatch` · 422 `iam.country-unavailable` · 422 `iam.username-not-phone` |
| IAM-R63 | displayName blank, > 120 characters or with control characters | register | 400 `VALIDATION_FAILED` (`displayName`) |
| IAM-R64 | no token · invalid token · a service token | register | 401 · 401 · 403 |
| IAM-R65 | a user with no IAM account | any other route of any service | 401 (unchanged) |
| IAM-R66 | the user just registered | `GET /me` and a call to case-service right after | 200 (no negative cache, D7) |
| IAM-R67 | the subject already has an account that is SUSPENDED or DEACTIVATED | register | 403 `PERMISSION_DENIED`; nothing created (self-registration never revives an account) |

## 2. Examples
| Example | Rule | Input | Expected |
|---|---|---|---|
| IAM-E60 | R60 | new subject, username `+919811122233`, `IN`, "Asha Pawar" | 201; user GROWER/IN, last 4 `2233`; grant GROWER OWN IN; one `iam.grant.created` |
| IAM-E61 | R61 | E60 again · E60's subject with `BR` | 200 same user id · 409 `DUPLICATE` |
| IAM-E62 | R62 | `+5516…` with `IN` · `XX` · username `asha` | 422 ×3 with the matching rule |
| IAM-E63 | R63 | `""` · 121 characters · `"A\u0000"` | 400 `displayName` |
| IAM-E64 | R64 | none · garbage · case-service client token | 401 · 401 · 403 |
| IAM-E65 | R65 | unprovisioned subject calls `GET /me` | 401 |
| IAM-E66 | R66 | after E60: `GET /me`; `GET /cases` on case-service (cache warmed with the unknown answer before) | 200; 200 (empty list) |
| IAM-E68 | R67 | a suspended grower's subject registers again | 403 |
| IAM-E67 | **smoke** (PRD J1) | Keycloak admin API creates a user like the registration page would; the user self-registers, registers as a grower (SPEC-GRW-01 R10), confirms the code (SPEC-GRW-03) | grower ACTIVE; the user raises a case |

## 3. API contract
```
POST /self-registration   {countryCode, displayName}   →  201|200 Me (as GET /me) · 400 · 401 · 403 · 409 · 422
```

## 4. Data & events
- V9: `iam.country.calling_code` (IN `91`, BR `55`); the check "phone HMAC and last 4 together" becomes "an HMAC needs its last 4" (D5: last 4 alone); audit action `user.self-register`.
- Outbox `iam.grant.created` (existing event type, the new grant).
- Keycloak realm (local-platform): `registrationAllowed: true`, user-profile validator on `username`, password policy; `gc-web` client unchanged (PKCE).

## 5. Security
| Concern | Rule |
|---|---|
| Who may self-register | any valid end-user token without an IAM account; only a GROWER/OWN grant can result (D3) |
| Abuse | one account per subject (D6); per-IP limits at the edge gateway (EDGE-01) |
| PII | last 4 digits only (D5); the phone never appears in logs or events |

## 6. Traceability
| Rule / Example | Test |
|---|---|
| R60–R65, R67 / E60–E65, E68 | `SelfRegistrationIT`, `SelfRegistrationRulesTest` |
| R66 / E66 | `SelfRegistrationIT` (IAM), gc-security `CachingPrincipalResolverTest` (no negative caching) |
| E67 | growercare-local-platform `smoke.sh` (section `grower`) |
