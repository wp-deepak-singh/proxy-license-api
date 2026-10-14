# 02: License file expiry rejects requests

**What to build:** When a gated request is decided from the installation license file, the gateway also checks the license file’s own expiry. A license that is still inside its stored expiry, or inside expiry plus grace, is not enough. If the file expiry (`meta.expiry`) is missing or the gateway’s current time is after that instant, the gated request is denied. The file expiry instant itself is still allowed.

This applies on every fallback. A signature-valid certificate whose inner license is still valid, or still inside grace, is denied once the file itself has expired. Exempt routes under `/api/client/auth` and `/actuator` stay allowed.

A certificate with a missing or past file expiry is not a covering certificate.

**Blocked by:** 01: Fallback decides from the installation license file

**Status:** ready-for-agent

- [x] On fallback, a gated request is denied when `meta.expiry` is missing, even if the inner license expiry is still in the future and the header key matches
- [x] On fallback, a gated request is denied when the gateway time is after `meta.expiry`, even if the inner license is inside stored expiry or inside grace and the header key matches
- [x] On fallback, a gated request is allowed when the file expiry instant has not passed, the inner license is covering, and the header key matches
- [x] The file-expiry check uses the certificate only and does not call Keygen
- [x] `/api/client/auth/**` and `/actuator/**` stay allowed when the license file itself has expired
