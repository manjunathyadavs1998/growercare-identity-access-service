# SPEC-IAM-01: Grant administration and effective grants
- **Requirements:** ACC-1, ACC-2, ACC-6, ACC-9 (audit), IAM-2
- **Status:** Implemented (written retroactively for increment 2)
- **Owner:** identity-access-service

## 1. Behaviour (rules)
| Rule | Given | When | Then |
|---|---|---|---|
| IAM-R1 | any caller | calls any API without a valid token (missing, forged, expired, wrong audience, wrong issuer) | 401 `UNAUTHENTICATED`, `WWW-Authenticate: Bearer` |
| IAM-R2 | valid token, no active account | calls any user API | 401 `UNAUTHENTICATED` |
| IAM-R3 | user | `GET /me` | 200; effective grants; territory scopes include all descendants; expired or revoked grants absent |
| IAM-R4 | caller without `grant:create` / `grant:read` / `grant:revoke` | calls the corresponding admin API | 403 `PERMISSION_DENIED` |
| IAM-R5 | admin | targets a user whose home country is outside the admin's scope | 404 `NOT_FOUND` |
| IAM-R6 | admin | grants a role above their own level | 422 `grant.delegation-level` |
| IAM-R7 | admin | requests a geo scope not covered by their own scope | 422 `grant.delegation-scope` |
| IAM-R8 | admin | grants to themselves | 422 `grant.self-grant` |
| IAM-R9 | admin | grants a role whose `allowed_user_type` ≠ the target's type | 422 `grant.user-type-mismatch` |
| IAM-R10 | admin | grants a grower/partner a scope other than exactly their home country | 422 `grant.scope-home-country` |
| IAM-R11 | target holds a role in `sod_conflict` with the requested one | grant | 422 `grant.sod-conflict` |
| IAM-R12 | target already holds the role actively | grant | 409 `DUPLICATE` |
| IAM-R13 | invalid input (unknown role/country, bad format, no geo scope, blank reason, malformed JSON) | grant | 400 `VALIDATION_FAILED` with `errors[].field` |
| IAM-R14 | valid grant | grant | 201, `Location`, audit SUCCESS, outbox `iam.grant.created` (IDs only), visible in `/me` of the target |
| IAM-R15 | any denial of IAM-R6…R12 | — | an audit row with outcome DENIED and the rule id survives the rolled-back request |
| IAM-R16 | active grant inside the admin's scope | `DELETE /grants/{id}?reason=` | 200 with `revokedAt`, audit + outbox `iam.grant.revoked`; second revoke → 422 `grant.already-revoked`; SoD conflict released |
| IAM-R17 | allow-listed service client (aud `gc-internal`) | `GET /internal/users/{sub}/principal` | 200 principal; unknown client → 401; user token → 403; service token on user API → 403 |
| IAM-R18 | allow-listed service client | `GET /internal/users/by-id/{userId}/principal` (SPEC-CASE-02 D2, assignee validation) | 200 principal of an active account; unknown or inactive id → 404; malformed id → 400 |

## 2. Examples
| Example | Rule | Actor | Input | Expected |
|---|---|---|---|---|
| IAM-E01 | R1 | — | no token / forged / expired / aud=some-other-api / foreign issuer | 401 UNAUTHENTICATED |
| IAM-E02 | R2 | random subject | GET /me | 401 |
| IAM-E03 | R3 | tm.in | GET /me | TERRITORY_MANAGER, territories ⊇ {1001,1002,1003}, ∌ 1005, has case:assign |
| IAM-E04 | R3 | agro.in with an expired STEWARDSHIP_OFFICER grant | GET /me | STEWARDSHIP_OFFICER absent |
| IAM-E05 | R4 | care.in | POST /grants | 403 |
| IAM-E06 | R4 | grower.in1 | GET /users/1/grants | 403 |
| IAM-E07 | R5 | admin.in | grant to user 105 (BR) | 404 |
| IAM-E08 | R6 | admin.in | user 102, GLOBAL_PLATFORM_ADMIN, IN | 422 grant.delegation-level |
| IAM-E09 | R7 | admin.in | user 102, CARE_AGENT, BR | 422 grant.delegation-scope |
| IAM-E10 | R8 | admin.in | user 104, QUALITY_INVESTIGATOR, IN | 422 grant.self-grant |
| IAM-E11 | R9 | admin.in | user 102, GROWER, IN | 422 grant.user-type-mismatch |
| IAM-E12 | R12 | admin.in | user 101, CARE_AGENT, IN | 409 DUPLICATE |
| IAM-E13 | R13 | admin.in | role NOT_A_ROLE | 400, field roleCode |
| IAM-E14 | R13 | admin.in | countryCodes ["india"], blank reason | 400 |
| IAM-E15 | R13 | admin.in | no geo scope | 400, field geo |
| IAM-E16 | R13 | admin.in | `{not json` | 400 |
| IAM-E17 | R14 | admin.in | user 101, QUALITY_INVESTIGATOR, IN, CP | 201 + audit + 1 outbox event |
| IAM-E18 | R11, R16 | admin.in | FINANCE_ANALYST to 103, then FINANCE_APPROVER; revoke analyst; approver again | 201, 422 sod-conflict, 200, 422 already-revoked, 201 |
| IAM-E19 | R17 | case-service / unknown-client / admin.in user token | GET /internal/... | 200 / 401 / 403 |
| IAM-E20 | R18 | case-service | by-id 102 / 999 / abc | 200 FIELD_AGRONOMIST / 404 / 400 |

**Unit examples (`GrantRules`, no I/O):**

| Example | Rule | Case | Expected |
|---|---|---|---|
| IAM-U01 | R7 | country admin IN → CARE_AGENT for IN / territory 1002 / region APAC (= {IN}) | allowed |
| IAM-U02 | R6 | country admin (60) → GLOBAL_PLATFORM_ADMIN (90) | grant.delegation-level |
| IAM-U03 | R7 | → BR, → territory 2002 (BR) | grant.delegation-scope |
| IAM-U04 | R7 | GLOBAL admin → BR | allowed |
| IAM-U05 | R8 | self | grant.self-grant |
| IAM-U06 | R9 | GROWER role to staff | grant.user-type-mismatch |
| IAM-U07 | R10 | grower scoped to a territory | grant.scope-home-country |
| IAM-U08 | — | suspended target | grant.user-not-active |
| IAM-U09 | R11 | FINANCE_APPROVER while FINANCE_ANALYST active | grant.sod-conflict |
| IAM-U10 | R12 | role already active | 409 |

## 3. API contract
| Method | Path | Request | Response | Errors |
|---|---|---|---|---|
| GET | `/me` | — | `{userId, userType, homeCountry, partnerOrgId, grants[{grantId, roleCode, scopeKind, piiClearance, permissions[], countryCodes[], territoryIds[], buCodes[], validTo}]}` | 401 |
| POST | `/grants` | `{userId, roleCode, regionCodes?, countryCodes?, territoryIds?, buCodes?, validTo?, reason}` | 201 GrantView + Location | 400, 401, 403, 404, 409, 422 |
| DELETE | `/grants/{grantId}?reason=` | — | 200 GrantView (revokedAt set) | 400, 401, 403, 404, 422 |
| GET | `/users/{userId}/grants` | — | 200 GrantView[] | 401, 403, 404 |
| GET | `/internal/users/{subject}/principal` | — | 200 GcPrincipal | 401, 403, 404 |
| GET | `/internal/users/by-id/{userId}/principal` | — | 200 GcPrincipal | 400, 401, 403, 404 |

All IDs are strings in public JSON; errors are RFC 9457 with `code`, `traceId` and (for 422) `rule`.

## 4. Data & events
- **Tables:** `iam.role_grant`, `grant_geo_scope`, `grant_bu_scope`, `audit_event`, `outbox` (`docs/backend/01_RDS_SCHEMA.md §3`).
- **Events:** `iam.grant.created` and `iam.grant.revoked` with `{grantId, userId, subject, roleCode, actorUserId}`.

## 5. Traceability
| Rule / Example | Test |
|---|---|
| U01–U10 | `GrantRulesTest` (parameterized) |
| E01, E02 | `IamSecurityIT$Authentication#invalidTokensAre401` (parameterized) |
| E03, E04 | `IamSecurityIT$EffectiveGrants` |
| E05–E16 | `IamSecurityIT$GrantAdministration#rejectedRequests` (parameterized) |
| E17 | `IamSecurityIT$GrantAdministration#validGrantIsAuditedAndPublished` |
| E18 | `IamSecurityIT$GrantAdministration#segregationOfDutiesThenRevocation` |
| E19 | `IamSecurityIT$InternalApi#internalApiAccess` (parameterized) |
| E20 | `IamSecurityIT$InternalApi#principalByUserId` (parameterized) |
| R15 | `IamSecurityIT$GrantAdministration#denialsAreAuditedOutsideTheRolledBackTransaction` |
