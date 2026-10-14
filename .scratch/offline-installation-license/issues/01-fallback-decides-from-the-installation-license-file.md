# 01: Fallback decides from the installation license file

**What to build:** When a gated request does not get a successful online license validation, the gateway decides from the installation license file alone. A gated route is any request the license filter already runs. Requests under `/api/client/auth` and `/actuator` stay exempt and are never denied by this check.

A successful online validation is one where Keygen answered, the validation is valid, and the license status is not expired, suspended, or banned. Everything else is a fallback: connection refused, connect timeout, read timeout, unknown host, an HTTP error, and every non-valid result, including expired, suspended, banned, and fingerprint mismatch.

On fallback, the request is allowed only when the installation license file is a covering certificate and the `X-License-Key` header equals the license key inside that certificate. The gateway does not contact Keygen during the fallback: no license lookup, no grace lookup, and no checkout.

A covering certificate has a valid signature, a visible stored license expiry (`data.attributes.expiry`), and a license key (`data.attributes.key`). The gateway’s current time is at or before that expiry. After expiry, the certificate still covers when `data.attributes.metadata.graceExpiryInHours` is a number and the time is at or before expiry plus those hours. The expiry instant and the grace deadline are still inside the window. A missing or non-numeric grace ends coverage at expiry.

A missing or blank `X-License-Key` on a gated route is denied and does not open the fallback.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] A gated request is allowed on connection refused, connect timeout, read timeout, or unknown host when the installation license file is covering and the header key matches, and that path makes no Keygen call
- [ ] A gated request is allowed on any non-valid Keygen result, including expired, suspended, banned, and fingerprint mismatch, when the file is covering and the header key matches, and that path does not check out or look up grace
- [ ] A gated request with a missing or blank `X-License-Key` is denied
- [ ] A gated request on fallback is denied when the file is missing, unreadable, badly signed, missing an expiry, missing a key, or the header key differs from the certificate key
- [ ] Before stored expiry, a covering file allows the request without a grace value
- [ ] After stored expiry, access lasts through expiry plus `graceExpiryInHours` when that value is a number, including the deadline instant
- [ ] After stored expiry, a missing or non-numeric grace denies the request
- [ ] `/api/client/auth/**` and `/actuator/**` stay allowed in every case above
