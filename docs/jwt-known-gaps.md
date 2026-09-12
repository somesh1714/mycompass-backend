# JWT Authentication — Known Gaps (To Review Later)

**Status:** Flagged for future review — not blocking, not a mistake, just tracked tech debt.
**Context:** The current JWT implementation (see `jwt-google-signin.html` in this folder) follows correct, industry-standard fundamentals — bearer token scheme, standard RFC 7519 claims (`sub`/`iat`/`exp`), stateless sessions, BCrypt hashing, no user-enumeration leak on password reset. The gaps below are the well-known differences between an MVP-stage JWT setup and a production system built for large-scale or adversarial traffic. Each is a deliberate, staged deferral, not an oversight — most already match the "deferred" list in the auth doc.

## Gaps

| Gap | What production systems typically do instead | Why it's acceptable to defer for now |
|---|---|---|
| **Single 24h access token, no refresh token** | Short-lived access token (5–15 min) + a longer-lived refresh token, so a stolen token has a small blast radius | Simpler to build for MVP; the tradeoff is a stolen token stays valid up to a full day |
| **No token revocation** | A server-side denylist, or a token-versioning scheme, so logout / password change / suspected compromise can invalidate a token before its natural expiry | True limitation of any stateless JWT — even today, resetting a password does **not** invalidate JWTs issued before the change |
| **Symmetric signing (HS256)** | Asymmetric signing (RS256/ES256) once multiple services need to *verify* tokens without being able to *issue* new ones | Correct as-is for a single-backend monolith, which is the current architecture |
| **Secret hardcoded in `application.properties`** | Environment variable or a secrets manager, never committed to source control | Already commented in code as dev-only; must fix before any real deployment |
| **No rate limiting on `/login` or `/forgot-password`** | Rate limiting or account lockout to blunt brute-force / credential-stuffing attacks | Already on the auth doc's explicitly deferred list |

## When to revisit

Reasonable triggers to come back to this list:
- Before any real (non-localhost) deployment — the hardcoded secret must move to an environment variable at minimum.
- If the backend ever splits into multiple services — switch to asymmetric signing (RS256) at that point.
- If abuse/brute-force becomes a real concern — add rate limiting before it's needed defensively, not after an incident.
- If "log out everywhere" / "invalidate sessions on password change" becomes a real product requirement — that needs either a token denylist or a move toward shorter-lived tokens + refresh tokens.

No action needed until one of these becomes relevant.
