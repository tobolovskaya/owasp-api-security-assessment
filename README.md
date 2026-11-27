# OWASP API security assessment: Juice Shop

> 🇳🇴 **Kort på norsk:** Sikkerhetsvurdering av REST-API-et i OWASP Juice Shop, en bevisst sårbar nettbutikk. Fem sårbarheter funnet med Postman, klassifisert etter OWASP API Security Top 10 (2023), STRIDE og CWE, med tiltak sortert etter prioritet.

## Executive summary

I tested the REST API of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), a deliberately vulnerable web shop, in a local Docker container. The goal was to find, classify and explain typical API vulnerabilities the way a security review for a real team would.

**Result: 5 vulnerabilities, 1 critical, 3 high and 1 medium.**

| # | Finding | Severity | What an attacker gets |
|---|---|---|---|
| 1 | SQL injection in product search | **Critical** | Read, and possibly change, the whole database without logging in |
| 2 | Any user can read any basket (IDOR) | **High** | Other customers' baskets, by changing a number in the URL |
| 3 | Any user can list all users | **High** | All accounts, including the admin email, for phishing or brute force |
| 4 | Registration accepts extra fields (mass assignment) | **High** | Possibly an admin account at sign-up; see the retest note |
| 5 | Password hash inside the login token | **Medium** | The user's MD5 password hash from any leaked token |

**The common root cause** is missing checks on the server: no ownership check, no role check, no allow-list of input fields, no parameterised SQL. All five are cheap to fix during development and expensive to find later.

**Top three actions:**
1. Parameterise every database query (fixes 1).
2. Add ownership and role checks in one shared middleware (fixes 2 and 3).
3. Accept only known fields on input and send only `sub`, `role`, `exp`, `iat` in the token (fixes 4 and 5).

**Skills shown:** API security testing · OWASP API Security Top 10 (2023) · STRIDE threat modelling · CWE classification · JWT analysis · Postman · Docker · writing findings for both developers and management

## Scope and method

| | |
|---|---|
| Target | OWASP Juice Shop (`bkimminich/juice-shop`) in Docker on localhost |
| Tools | Postman for requests, jwt.io to decode tokens; Semgrep for a separate SAST cross-check |
| Accounts | Test accounts in the local instance; no real data |
| Framework | OWASP API Security Top 10 (2023), STRIDE, CWE |
| Not in scope | Rate limiting (API4), SSRF (API7), DAST scanning |

Juice Shop is built to be insecure and runs only on my own machine. Only test systems you own or have written permission to test.

## Findings

| # | Endpoint | Method | Auth | Vulnerability | OWASP API 2023 | STRIDE | CWE |
|---|---|---|---|---|---|---|---|
| 1 | `/rest/products/search?q=` | GET | No | SQL injection | (not an API Top 10 category; OWASP Top 10 A03:2021 Injection) | Tampering, Information Disclosure | CWE-89 |
| 2 | `/rest/basket/{id}` | GET | Yes | IDOR | API1 Broken Object Level Authorization | Elevation of Privilege | CWE-639 |
| 3 | `/api/Users` | GET | Yes | Missing role check | API5 Broken Function Level Authorization | Elevation of Privilege | CWE-285 |
| 4 | `/api/Users` | POST | No | Mass assignment | API3 Broken Object Property Level Authorization | Elevation of Privilege | CWE-915 |
| 5 | `/rest/user/login` | POST | No | Password hash in JWT | API3 Broken Object Property Level Authorization | Information Disclosure | CWE-200 |

### 1. SQL injection in product search (critical)

The search term goes straight into the SQL query.

```http
GET /rest/products/search?q=')) -- HTTP/1.1
```

The quote and brackets close the `LIKE` condition and `--` comments out the rest, so the query returns **every product**. With a `UNION SELECT` an attacker can read other tables, such as users and password hashes.

**Impact:** read the database without logging in, and with stacked or modifying queries, change it.

**Fix:** parameterised queries or the ORM for every query. Juice Shop runs on Node.js with Sequelize. An illustration of the pattern and the fix:

```javascript
// vulnerable: user input inside the SQL string
sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${q}%'`)

// safe: input passed as a bound parameter
sequelize.query('SELECT * FROM Products WHERE name LIKE :q', {
  replacements: { q: `%${q}%` },
})
```

A WAF rule can catch common payloads, but it is a second layer, not the fix.

### 2. Any user can read any basket: IDOR (high)

A logged-in customer (user 23) changes the basket id in the URL and gets someone else's basket.

```http
GET /rest/basket/7 HTTP/1.1
Authorization: Bearer <token of user 23>
```

```json
{ "status": "success", "data": { "id": 7, "UserId": 24, "Products": [ ... ] } }
```

**Impact:** basket ids are sequential, so trying 1, 2, 3… reveals every customer's basket. If write endpoints have the same gap, baskets can be changed too.

**Fix:** check ownership on the server for every object.

```javascript
const basket = await Basket.findByPk(req.params.id)
if (!basket) return res.status(404).end()
if (basket.UserId !== req.user.id && req.user.role !== 'admin') {
  return res.status(403).json({ error: 'Access denied' })
}
```

Random UUIDs instead of 1, 2, 3 make guessing harder, but they do not replace the ownership check.

### 3. Any user can list all users (high)

`GET /api/Users` with an ordinary customer token returns every account, including the administrator.

```json
{ "data": [ { "id": 1, "email": "admin@juice-sh.op", "role": "admin" }, { "id": 2, "email": "jim@juice-sh.op" } ] }
```

**Impact:** personal data of all users, and the admin email as a target for phishing and password guessing.

**Fix:** a role check in shared middleware, so a new admin endpoint cannot forget it.

```javascript
const requireRole = (role) => (req, res, next) =>
  req.user?.role === role ? next() : res.status(403).json({ error: 'Forbidden' })

app.get('/api/Users', requireRole('admin'), listUsers)
```

### 4. Registration accepts extra fields: mass assignment (high)

The registration endpoint copies the request body onto the user object without an allow-list of fields.

```http
POST /api/Users HTTP/1.1
Content-Type: application/json

{ "email": "attacker@example.com", "password": "12345678", "passwordRepeat": "12345678", "isAdmin": true }
```

**Impact:** fields such as the role can be set by the client at sign-up.

> **Retest note.** The original test sent `isAdmin: true`, and the response was not saved as evidence. Finding 5 shows that Juice Shop stores the role in a field called `role` (`"role": "customer"`). The next test should send `"role": "admin"` and record the response, to confirm the escalation instead of assuming it.

**Fix:** accept only known fields and set sensitive ones on the server.

```javascript
const { email, password, passwordRepeat, securityQuestion } = req.body
const user = await User.create({ email, password, securityQuestion, role: 'customer' })
```

### 5. Password hash inside the login token (medium)

The JWT returned by `POST /rest/user/login` carries the whole user record, including the password hash.

```json
{ "id": 23, "email": "student@example.com", "password": "048fe686fd7f8cad6e4d9ac6e400c120", "role": "customer", "totpSecret": "" }
```

A JWT is only signed, not encrypted: anyone who sees the token, for example through XSS or a log file, can read it.

**Impact:** the hash is unsalted MD5, which is fast to crack with rainbow tables or brute force.

**Fix:** keep the token minimal (`sub`, `role`, `exp`, `iat`), keep it short-lived (5–15 minutes), store it in an `HttpOnly` cookie, and hash passwords with bcrypt or Argon2id.

## Why these STRIDE and CWE labels

**Finding 3: Elevation of Privilege, CWE-285 Improper Authorization.** The user is correctly authenticated, so it is not Spoofing or CWE-287. The problem is that a customer can use a function meant for admins: the authorization check is missing. CWE-862 Missing Authorization would also fit, and CWE-284 is too broad.

**Finding 1: Tampering and Information Disclosure, CWE-89.** The input changes the structure of the SQL command (tampering), and the usual result is data leaving the database (disclosure). CWE-89 describes exactly this: an SQL command built from outside input without neutralising special characters.

## Remediation plan

| When | What | Fixes |
|---|---|---|
| **Now (1–2 weeks)** | Parameterised queries everywhere; shared ownership and role middleware; minimal JWT payload | 1, 2, 3, 5 |
| | Allow-list input fields on all create and update endpoints | 4 |
| **Next (1–3 months)** | Central authorization policy (for example OPA), rate limiting and schema validation in an API gateway, structured logs with a trace id | defence in depth |
| **Later (3–6 months)** | SAST, dependency and DAST scans as blocking CI gates; alerts on repeated 403s and SQL errors | find the next one earlier |

## Coverage against OWASP API Security Top 10 (2023)

| Risk | Result |
|---|---|
| API1 Broken Object Level Authorization | ✅ found: finding 2 |
| API2 Broken Authentication | ⚠️ related: weak token content, finding 5 |
| API3 Broken Object Property Level Authorization | ✅ found: findings 4 and 5 |
| API4 Unrestricted Resource Consumption | not tested |
| API5 Broken Function Level Authorization | ✅ found: finding 3 |
| API6 Unrestricted Access to Sensitive Business Flows | not tested |
| API7 Server Side Request Forgery | not tested |
| API8 Security Misconfiguration | not tested |
| API9 Improper Inventory Management | not tested |
| API10 Unsafe Consumption of APIs | not tested |

## SAST cross-check: what Semgrep found and missed

To compare manual testing with static analysis, I ran Semgrep 1.144.1 with the `p/owasp-top-ten` ruleset on the Juice Shop source:

```bash
docker run --rm -v "$(pwd)":/src returntocorp/semgrep semgrep --config p/owasp-top-ten /src --json -o semgrep-owasp-top-ten.json
```

Semgrep reported **18 findings** (7 ERROR, 11 WARNING). Raw output: [`sast/semgrep-owasp-top-ten.json`](sast/semgrep-owasp-top-ten.json). I triaged each one against the code:

| Verdict | Count | Findings |
|---|---|---|
| Confirmed in running code | 9 | SQL injection in `routes/search.ts` (same as finding 1) and `routes/login.ts`; `eval()` on user input in `routes/userProfile.ts`; hardcoded RSA private key used to sign tokens in `lib/insecurity.ts`; open redirect in `routes/redirect.ts` (allow-list checked with `includes()`); file download in `routes/fileServer.ts` (null-byte bypass of the file-type check); directory listing on `/ftp`, `/encryptionkeys` and `/support/logs` |
| Low, by design | 1 | Directory listing on `/.well-known` |
| Path traversal blocked | 3 | `res.sendFile` in key, log and quarantine servers: names with `/` are rejected (the exposed folders are already counted above) |
| Not running code | 4 | SQL injection in `data/static/codefixes/*`: answer options for the coding challenges, not routes |
| Not confirmed | 1 | `raw-html-format` in `routes/chatbot.ts`: the string is returned inside JSON, not rendered as HTML |

**Compared with the manual assessment:**

| Manual finding | Found by Semgrep? |
|---|---|
| 1. SQL injection in product search | Yes |
| 2. IDOR on baskets | No |
| 3. Any user can list all users | No |
| 4. Mass assignment on registration | No |
| 5. Password hash inside the token | No |

Semgrep found the injection, plus code-level issues outside the API scope of this report (`eval`, the hardcoded key, directory listing). It found none of the four access-control and data-exposure findings: those need knowledge of who is allowed to do what, which is not in the code patterns. DAST with OWASP ZAP was planned but not run, so it is not part of this comparison.

## Hva jeg lærte / What I learned

- **Authentication is not authorization.** Three of the five findings happen with a valid token. The server checked who I was, not what I was allowed to do.
- **Classifying is harder than finding.** Mapping SQL injection correctly took a second look: the 2023 API Top 10 has no injection category, so it belongs to the general OWASP Top 10 instead.
- **SAST and manual testing find different things.** Semgrep found 1 of my 5 findings, but also 8 confirmed issues I had not looked for. Only 9 of its 18 results held up after triage.
- **Evidence or it did not happen.** Writing this up again showed that one finding (mass assignment) was assumed, not proven. A finding without a saved response is a hypothesis.

---

Originally written as coursework during my MSc in Computer Science (Woolf / GoIT Neoversity, course Secure Software Development and Integration), then translated, corrected and restructured as an assessment report.

**Sources:** [OWASP API Security Top 10 2023](https://owasp.org/API-Security/) · [CWE Top 25](https://cwe.mitre.org/top25/) · [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) · [Microsoft STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)

**Yevheniia Tobolovska** · IT operations and security · [Portfolio](https://tobolovska.no) · [LinkedIn](https://www.linkedin.com/in/yevheniia-tobolovska)

License: [MIT](LICENSE)
