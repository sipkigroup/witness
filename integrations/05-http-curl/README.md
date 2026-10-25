# 05 - Plain HTTP / curl

```
export DW_URL=https://witness.sipkigroup.com DW_KEY=dwk_...
./witness.sh act send_email '{"to":"bob@partner.example","subject":"hi","body":"..."}'   # -> {"rid","verdict","reason","status","aar_b64",...}
./witness.sh present RID      # allow: consume the receipt BEFORE acting -> {"result":"accept"}; a second present -> reject
# ... do the thing ...
./witness.sh report RID true  # executed? (self-reported)
./witness.sh get RID 25       # defer: long-poll up to 25 s; after the owner approves: verdict allow, status approved
./witness.sh info             # witness key (public); pin it, and verify aar_b64 yourself (Python SDK verify_aar)
```
Errors are `{"error": CODE, "detail": ...}` with HTTP 4xx (`BAD_KEY` 401, `RATE_LIMIT`/`QUOTA` 429: 300 requests/min per key). Treat any error or timeout as **deny**.
Poll with whole-second `wait` (0..25) and sleep between polls if you use `wait=0`: `GET` counts against the 60/min limit.

## Test
`pytest -q .`: deny (`RECIPIENT`), allow + `present` accept then reject (single use) + `report`, `pass`, `defer` -> long-poll -> owner approves -> `allow`/`approved`/`OK_APPROVED`, retry returns the same rid; wrong key -> 401 `BAD_KEY`.
