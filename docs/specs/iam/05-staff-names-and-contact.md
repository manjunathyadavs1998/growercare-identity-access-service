# SPEC-IAM-05: Staff names for the UI and staff contact for notifications
- **Requirements:** SPEC-FE-03 R205 follow-up (overview workload by name), SPEC-NOT-02 D4 (assignment email), PRV-5
- **Status:** Implemented
- **Owner:** identity-access-service
- **IDs:** rules IAM-R120+, examples IAM-E120+

## 0. Decisions
| # | Decision | Why |
|---|---|---|
| D1 | **`GET /users/names?ids=1,2,…`** (≤ 100 ids) returns `{userId, displayName}` for **STAFF** users only, to **staff** callers holding `case:read` or `dashboard:read` (growers and partners see "the GrowerCare team", never names); other ids (growers, partners, unknown, other countries outside the caller's grants) are simply absent | Staff names are work data (SPEC-IAM-02 D3); growers' names never leave through this |
| D2 | **`GET /internal/users/by-id/{id}/contact`** returns `{email, displayName, language}` of an ACTIVE STAFF or PARTNER user to allow-listed service clients (`GC_CONTACT_CLIENTS`: notification-service) | Assignment emails (NOT-02) without copying emails elsewhere |
| D2a | **Each internal route group has its own allow-list:** `GC_PRINCIPAL_CLIENTS` (the services that authorise users) for principal resolution, `GC_CONTACT_CLIENTS` (notification-service) for contacts. `GC_INTERNAL_CLIENTS` only admits the token; the sender never resolves principals with grants | Least privilege (review) |
| D3 | The staff language defaults to `en` (no staff language preference in Phase 1) | — |

## 1. Behaviour (rules)
| Rule | Given | When | Then |
|---|---|---|---|
| IAM-R120 | a STAFF user with `case:read` or `dashboard:read` | `GET /users/names?ids=` | 200 the STAFF among the ids whose home country is in the caller's grants (or GLOBAL) |
| IAM-R121 | not staff, or neither permission (a grower holds `case:read` but is not staff) · > 100 ids or a malformed id | names | 403 · 400 |
| IAM-R122 | a `GC_CONTACT_CLIENTS` service token | contact | 200 `{email, displayName, language}` for ACTIVE staff/partner **with an email**; 404 for growers, inactive, unknown, or no email (`email` is optional in IAM) |
| IAM-R123 | a user token · another internal service client | contact | 403 · 403 (as every /internal route answers end-user tokens, IAM-E19c) |
| IAM-R124 | notification-service (a contact client, not a principal reader) | `GET /internal/users/{subject}/principal` or `…/by-id/{id}/principal` | 403 |

## 2. Examples
| Example | Rule | Input | Expected |
|---|---|---|---|
| IAM-E120 | R120 | tm.in, ids 102,1,105 | only 102 (Vikram Agro): 1 is a grower, 105 is Brazilian |
| IAM-E120b | R120 | a GLOBAL executive (dashboard:read), ids 102,105 | both (GLOBAL covers every country) |
| IAM-E121 | R121 | grower.in1 · admin.in (staff, neither permission) · 101 ids · `ids=abc` · grower.in1 with `ids=abc` | 403 · 403 · 400 · 400 · 403 (authorised first) |
| IAM-E122 | R122 | notification-service, 102 · 1 · a staff user without email · a suspended staff user | agro.in's email · 404 · 404 · 404 |
| IAM-E123 | R123 | care.in token · case-service token | 403 · 403 |
| IAM-E124 | R124 | notification-service on both principal routes | 403 · 403 |

## 6. Traceability
| Rule / Example | Test |
|---|---|
| R120–R124 / E120–E124 | `StaffNamesAndContactIT` |
