# R2R: three security issues (auth bypass via a default JWT key, two SQL injections)

**Status:** DRAFT, not yet sent. Do not share publicly.
**To:** SciPhi-AI/R2R maintainers, via GitHub private vulnerability reporting (Security → Report a vulnerability)
**From:** [your name / contact]
**Date:** [date sent]

## Summary

| # | Issue | Severity (our estimate) | Who can trigger it |
|---|---|---|---|
| 1 | The JWT signing key falls back to a key hard-coded in the public source | Critical | Anyone, against deployments with authentication on and no `R2R_SECRET_KEY` set |
| 2 | SQL injection through metadata filter keys in search | High | Any user who can search |
| 3 | SQL injection in `CREATE INDEX` through `index_name` | High | Any authenticated user |

Together, issue 1 gives an attacker a superuser token, and issues 2 and 3 give them the database.

We found these by reading the source; we have not run R2R or any proof of concept. Please confirm against your current release.

**Version reviewed:** commit `9c5a94d151f90876bd7eb860f300a8fd662dc481` (2025-11-06), `py/pyproject.toml` version 3.6.6.

---

## 1. Default JWT signing key in source (CWE-798, CWE-1394)

**Files:** `py/core/providers/crypto/bcrypt.py` (around lines 17 and 63) and `py/core/providers/crypto/nacl.py` (around lines 18 and 58)

Both crypto providers choose the HS256 signing key like this:

```python
self.secret_key = (
    config.secret_key
    or os.getenv("R2R_SECRET_KEY")
    or DEFAULT_BCRYPT_SECRET_KEY   # DEFAULT_NACL_SECRET_KEY in nacl.py
)
```

`DEFAULT_BCRYPT_SECRET_KEY` and `DEFAULT_NACL_SECRET_KEY` are 43-character literals in the public repository. The comment above the bcrypt code says "No fallback defaults: fail if not provided", but the code does fall back.

The shipped environment files `docker/env/r2r.env` and `docker/env/r2r-full.env` contain `R2R_SECRET_KEY=` with an empty value. An empty string is falsy, so a deployment built from these files signs tokens with the public default key.

**Why a forged token is accepted:** `R2RAuthProvider.decode_token` (`py/core/providers/auth/r2r_auth.py`, around line 106) checks only that:
- the HS256 signature is valid;
- `sub`, `token_type` and `exp` are present;
- the token is not blacklisted.

It then loads the user by the email in `sub`. A token signed with the default key, with claims `sub` = a user's email, `token_type` = `access` and a future `exp`, is accepted for that user. The default superuser email is `admin@example.com` in both `r2r.toml` and `r2r_with_auth.toml`.

**Affected:** deployments with `require_authentication = true` that do not set their own key. Operators who turn authentication on, for example from `r2r_with_auth.toml`, reasonably believe they are protected.

**Impact:** an attacker can log in as any account, including the superuser. That gives access to every user's documents, collections and admin functions.

**Suggested fix:**
- Remove both default keys and refuse to start when no key is configured.
- Treat an empty value as unset.
- Optionally generate a random key on first start and save it.
- Consider rotating the key in your release notes, since anyone may have read the old default.

## 2. SQL injection through search-filter keys (CWE-89)

**Files:** `py/core/providers/database/filters.py` (`_build_metadata_operator_condition`), used for example by the hybrid document search in `py/core/providers/database/documents.py` (around line 775)

Filter **values** are passed as bound parameters, but metadata filter **keys** are put into the SQL text without escaping:

```python
quoted_key = f"'{path_parts[0]}'"                       # single segment
path_literal = "'{" + ",".join(f'"{p}"' for p in path_parts) + "}'"  # dotted path
```

Users control the keys through `search_settings.filters` (for example `{"metadata.<key>": {"$eq": ...}}`) on the search endpoints. A key containing `'` ends the string literal, and the rest of the key becomes SQL in the `WHERE` clause.

**Impact:**
- The user's filters are combined with R2R's owner and collection restriction in the same `WHERE` clause. An injected condition can likely bypass that restriction and read other users' documents.
- What else is possible depends on the database role.
- On deployments with authentication off, anyone who can reach the API can do this.

**Suggested fix:**
- Bind the JSON path as a parameter (`metadata #>> $n::text[]`, `metadata -> $n`).
- Or reject keys that do not match a strict pattern such as `^[A-Za-z0-9_\-]+$`.

## 3. SQL injection in `CREATE INDEX` through `index_name` (CWE-89)

**Files:** `py/core/providers/database/chunks.py` (around line 906); entry point `POST /v3/indices` in `py/core/main/api/v3/indices_router.py`

```python
create_index_sql = f"""
CREATE INDEX {concurrently_sql} {index_name}
ON {table_name_str}
USING {index_method} ({col_name} {ops}) ...;
"""
await conn.execute(create_index_sql)
```

`index_name` comes from the request body (`IndexConfig.index_name`) and is pasted into the statement as is. The route depends only on `auth_wrapper()`, so any authenticated user can call it; there is no superuser check.

**Impact:** an authenticated user can inject DDL or DML that runs with R2R's database role, for example dropping or changing tables.

**Suggested fix:**
- Restrict index management to superusers.
- Validate `index_name` as an identifier, or quote it with your driver's identifier quoting.
- Apply the same treatment to the other values in this statement that come from the request.

---

## Disclosure

- Reported privately. We will not publish details before a fix is available, or before an agreed date (we suggest 90 days).
- We are happy to answer questions or review a patch.
- No proof-of-concept code has been run against any deployment.

---

<!-- Notes for the sender (delete before sending):
- Recheck each file and line on the current R2R main branch; lines may have moved since commit 9c5a94d.
- Do not paste the default key value into the report; the maintainers know it.
- Supporting evidence: ~/Desktop/codepulse-reports/issues/SciPhi-AI__R2R/
-->
