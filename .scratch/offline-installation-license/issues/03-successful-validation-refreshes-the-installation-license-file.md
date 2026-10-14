# 03: Successful validation refreshes the installation license file

**What to build:** After a gated request passes online validation, the gateway checks out installation license `07726a83-4b3d-4b9b-adbc-f9f6c986732f` and waits for that checkout before allowing the request. The new certificate replaces the installation license file only when it is a covering certificate under the same rules as the fallback, including the license file’s own expiry. If checkout fails, or the new certificate does not cover, the previous file stays and the request is still allowed. A fallback result does not check out.

**Blocked by:** 02: License file expiry rejects requests

**Status:** ready-for-agent

- [x] Every gated request with a successful online validation checks out license `07726a83-4b3d-4b9b-adbc-f9f6c986732f` before the request is allowed
- [x] The new certificate replaces the installation license file only when it is covering, including a visible file expiry that the gateway’s current time has not passed
- [x] A failed checkout, or a new certificate that does not cover, leaves the previous file in place and the gated request is still allowed
- [x] An expired, suspended, banned, fingerprint-mismatch, or other non-valid result does not check out
- [x] A transport failure does not check out
- [x] `/api/client/auth/**` and `/actuator/**` are unchanged
