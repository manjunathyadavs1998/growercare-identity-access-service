# SPEC-IAM-02: User directory for administrators
- **Requirements:** ACC-1/ACC-2 (grants are given to people the admin can find), PRV-5, Phase 1 PRD journey **J8** (admin grants and revokes) and UI scope "admin: users and grants", M3
- **Status:** Implemented
- **Owner:** identity-access-service
- **IDs:** rules IAM-R80+, examples IAM-E80+

## 0. Decisions (to agree with this spec)
| # | Decision | Why |
|---|---|---|
| D1 | **Read-only directory in Phase 1:** `GET /users` (search) and `GET /users/{id}`. Creating staff and partner accounts stays a Keycloak/seed task; suspending users is Phase 2 | J8 needs to find a person and manage their grants (which exists); account lifecycle needs a Keycloak admin integration of its own |
| D2 | **Same visibility as grant administration:** `user:read` and the user's home country inside the admin's country scope (`GrantRules.canAdminister`, SPEC-IAM-01). Everything else is 404 (single user) or absent (search) | One rule for "which users may this admin see" |
| D3 | **Grower names are personal data:** a GROWER user's display name is masked (`R***** P****`) unless the admin's `user:read` grant has FULL clearance; staff and partner names are shown. Only the phone's last 4 digits ever appear | PRV-5; staff names are work data |
| D4 | **Search:** `q` matches the start of a display-name word (case-insensitive, at least 2 characters) or an exact user id; filters `type` (GROWER/PARTNER/STAFF), `country`, `status`; 20 per page, keyset by user id | Enough to find "Vikram" or user 102 quickly; no full-text engine |
| D5 | **The single-user view includes the user's active grants** (role, scope, valid to), so the admin screen needs one call per person; list rows carry no grants (one query per page, not one per row) | The grant list endpoint exists, but the detail screen is what the admin works in |
| D6 | **A masked admin cannot search grower names:** `q` matches a GROWER user's name only where the admin may see it unmasked; growers stay findable by user id | Otherwise searching "ram" would confirm a masked name letter by letter |

## 1. Behaviour (rules)
| Rule | Given | When | Then |
|---|---|---|---|
| IAM-R80 | admin with `user:read` | `GET /users?q=&type=&country=&status=&cursor=` | 200 `{items, nextCursor}`: users visible to the admin (D2), matching every filter, ordered by user id |
| IAM-R81 | same | `GET /users/{id}` | 200 user view with active grants; 404 when not visible or unknown |
| IAM-R82 | a GROWER user, admin without FULL clearance | list or read | display name masked; `phoneLast4` only (D3) |
| IAM-R83 | `country` outside the admin's scope | search | empty page (D2: never a hint that users exist there) |
| IAM-R84 | `q` shorter than 2 characters (and not an id) · unknown `type` or `status` · malformed cursor | search | 400 naming the field |
| IAM-R85 | no `user:read` (care agent, grower, retailer user) | either | 403 |
| IAM-R86 | admin without FULL clearance for the grower's country | `q` = part of a grower's name | the grower is not matched (D6); by user id it is |

## 2. Examples
| Example | Rule | Actor | Input | Expected |
|---|---|---|---|---|
| IAM-E80 | R80 | admin.in (COUNTRY_ADMIN, IN, MASKED) | `q=vik` · `type=STAFF` · `q=102` | Vikram Agro (102) · the IN staff · user 102 |
| IAM-E81 | R81 | admin.in | user 102 · user 105 (BR) · 999999 | 200 with grants · 404 · 404 |
| IAM-E82 | R82 | admin.in | `type=GROWER` | Ramesh Patil shown as `R***** P****`, Sunita Rao masked; no phone beyond the last 4 |
| IAM-E83 | R83 | admin.in | `country=BR` | empty page |
| IAM-E84 | R84 | admin.in | `q=v` · `type=ROBOT` · `cursor=!!` | 400 `q` · `type` · `cursor` |
| IAM-E85 | R85 | care.in · grower.in1 · retailer.in | `GET /users` | 403 |
| IAM-E87 | R82/R86 | a DPO (user:read, FULL, India) · admin.in | `q=ramesh` · `q=1` | DPO: Ramesh Patil unmasked · admin.in: no match by name, `R***** P****` by id |
| IAM-E86 | **smoke** (PRD J8) | admin.in finds agro.in in the directory, grants a temporary role in another territory, then revokes it | through the edge gateway | user found; grant 201; revoke 200; case-service sees the change within seconds (existing eviction) |

## 3. API contract
```
GET /users?q=&type=&country=&status=&cursor=&limit=(1–100, default 20)     200 {items: [UserSummary], nextCursor?} · 400 · 403
GET /users/{userId}                               200 UserView · 403 · 404
UserSummary = {userId, userType, homeCountry, partnerOrgId?, displayName, phoneLast4?, status}
UserView = UserSummary + {grants: [GrantView]}   (active grants only; GET /users/{id} only)
```

## 4. Data & events
- V10: index `user_account_name_ix (lower(display_name) text_pattern_ops)` for name prefixes; word-start matches scan the country's users (small in Phase 1).
- No events.

## 5. Security
| Concern | Rule |
|---|---|
| Permission | `user:read` (R85) |
| Scope | D2; BR users invisible to IN admins and vice versa |
| PII | grower names masked per clearance; last 4 phone digits only (D3) |

## 6. Traceability
| Rule / Example | Test |
|---|---|
| R80–R86 / E80–E85, E87 | `UserDirectoryIT` |
| E86 | growercare-local-platform `smoke.sh` |
