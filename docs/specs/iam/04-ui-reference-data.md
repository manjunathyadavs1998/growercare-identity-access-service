# SPEC-IAM-04: Reference data and assignable staff for the UI
- **Requirements:** PRD M4 (UI without hard-coded country data, convention 4), J5 (care assigns an agronomist), J8 (admin grants a role with a scope), J9 (workload names); SPEC-FE-02 D4, SPEC-FE-03 D3/R205/R206
- **Status:** Implemented
- **Owner:** identity-access-service
- **IDs:** rules IAM-R100+, examples IAM-E100+

## 0. Decisions
| # | Decision | Why |
|---|---|---|
| D1 | **Territories:** `GET /reference/territories?country=` returns the country's territory tree (id, parent, code, name, level). Any signed-in user, for their home country and the countries their grants cover; another country is 404 | Registration, queue filters, overview and grant forms need it; territory names are not personal data |
| D2 | **Grantable roles:** `GET /reference/roles` lists the roles **this admin may grant**: role level not above the admin's own `grant:create` grants (SPEC-IAM-01 delegation, ACC-2), with scope kind and user type. User type and scope are still checked per grant (the form filters roles by the chosen user's type). Needs `grant:create` | The form offers only what would be accepted |
| D3 | **Assignable staff:** `GET /users/assignable?territoryId=&buCode=` lists STAFF users whose active grants carry `case:transition` and cover that territory (itself, an ancestor, its country, its country's region, or GLOBAL) and BU (no BU scope = every BU). Needs `case:assign`. Returns user id, display name and role codes only. case-service still checks the assignee on `PUT /assignee` | Care can pick an agronomist without the full user directory (`user:read`), and sees only people who could take the case |

## 1. Behaviour (rules)
| Rule | Given | When | Then |
|---|---|---|---|
| IAM-R100 | any signed-in user | `GET /reference/territories` (country defaults to home) | 200 the tree, ordered by level then name |
| IAM-R101 | `country` neither home nor covered by a grant · unknown | territories | 404 |
| IAM-R102 | admin with `grant:create` | `GET /reference/roles` | 200 every role whose level ≤ the highest level among the admin's `grant:create` grants, ordered by level then code |
| IAM-R103 | no `grant:create` | roles | 403 |
| IAM-R104 | `case:assign` | `GET /users/assignable?territoryId=T&buCode=B` | 200 ACTIVE staff with a `case:transition` grant covering T (T, an ancestor, its country or region, or GLOBAL) and B, by display name |
| IAM-R105 | no `case:assign` grant of the caller covers both T (geo) and B (BU) · T unknown | assignable | 404 |
| IAM-R106 | no `case:assign` | assignable | 403 |

## 2. Examples
| Example | Rule | Actor | Input | Expected |
|---|---|---|---|---|
| IAM-E100 | R100 | grower.in1 | (no country) | India: Maharashtra › Pune, Nashik; Karnataka › Bengaluru Rural |
| IAM-E101b | R100 | a test care agent at home in India with a CARE_AGENT grant for Brazil | `country=BR` | 200 Brazil's territories (covered by a grant) |
| IAM-E101 | R101 | grower.in1 · care.in | `country=BR` · `country=XX` | 404 · 404 |
| IAM-E102 | R102 | admin.in (COUNTRY_ADMIN, level 60) | — | includes CARE_AGENT, FIELD_AGRONOMIST, TERRITORY_MANAGER, COUNTRY_ADMIN (same level is allowed by SPEC-IAM-01); excludes DPO (65), REGIONAL_ADMIN (70), GLOBAL_PLATFORM_ADMIN (90) |
| IAM-E103 | R103 | care.in | — | 403 |
| IAM-E104 | R104 | care.in | Pune 1002, CP | agro.in (Vikram Agro), tm.in (Kiran Territory), care.in; not care.br |
| IAM-E105 | R105 | care.in · tm.in | 999999 · Bengaluru Rural 1005 | 404 · 404 |
| IAM-E105b | R105 | a test territory manager for Pune limited to BU SEEDS | Pune 1002 with CP · with SEEDS | 404 · 200 |
| IAM-E106 | R106 | agro.in · grower.in1 | 1002, CP | 403 |

## 3. API contract
```
GET /reference/territories?country=IN     200 [{territoryId, parentTerritoryId?, code, name, level}] · 404
GET /reference/roles                      200 [{roleCode, name, scopeKind, allowedUserType}] · 403
GET /users/assignable?territoryId=&buCode= 200 [{userId, displayName, roleCodes[]}] · 400 · 403 · 404
```

## 6. Traceability
| Rule / Example | Test |
|---|---|
| R100–R106 / E100–E106, E101b, E105b | `UiReferenceDataIT` |
