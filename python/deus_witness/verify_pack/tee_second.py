"""Second TDX quote verifier (0.2.41): the same quote, the same saved Intel collateral, judged by dcap-qvl (Rust, MIT) next to tdx_quote.py.
Optional: `pip install "deus-witness[tee]"`. Offline: no network, no Intel PCS call. NOT a replacement: report_data binding, the expected
measurements, the DEBUG bit, the event-log replay and the pinned Intel root stay with tdx_quote.py (dcap-qvl does none of them).
run() never raises; it returns {"state": "AGREE" | "DISAGREE" | "NOT_INSTALLED" | "NOT_RUN", ...}."""
import json
import os
import time

NAME = "dcap-qvl"
# The Phala platform (dstack, TDX): dynamic platform, cached keys, SMT on. dcap-qvl's strict policy refuses all three, so we allow them
# explicitly and print them: the choice is visible to whoever reads the output.
PHALA_FLAGS = (("dynamic_platform", "allow_dynamic_platform"), ("cached_keys", "allow_cached_keys"), ("smt_enabled", "allow_smt"))
INSTALL = 'install deus-witness[tee] (pip install "deus-witness[tee]")'
_FILES = ("tcb_info.json", "tcb_info_issuer_chain.pem", "qe_identity.json", "qe_identity_issuer_chain.pem",
          "pck_crl.der", "pck_crl_issuer_chain.pem", "root_ca_crl.der")


def _raw_member(txt, key):
    """The exact text of the object under `key` (the Intel signature covers these bytes: no re-serialising). String-aware."""
    i = txt.index('"%s"' % key) + len(key) + 2
    i = txt.index("{", i)
    depth, instr, esc = 0, False, False
    for j in range(i, len(txt)):
        c = txt[j]
        if instr:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                instr = False
        elif c == '"':
            instr = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return txt[i:j + 1]
    raise ValueError("unbalanced JSON in %s" % key)


def collateral_json(col_dir):
    """Our collateral directory (tdx_quote.py --fetch-collateral) -> dcap-qvl QuoteCollateralV3 JSON. No PCK chain: it comes from the quote."""
    def rd(n, mode="r"):
        with open(os.path.join(col_dir, n), mode) as f:
            return f.read()
    t, q = rd("tcb_info.json"), rd("qe_identity.json")
    return json.dumps({
        "tcb_info": _raw_member(t, "tcbInfo"), "tcb_info_signature": json.loads(t)["signature"],
        "qe_identity": _raw_member(q, "enclaveIdentity"), "qe_identity_signature": json.loads(q)["signature"],
        "tcb_info_issuer_chain": rd("tcb_info_issuer_chain.pem"), "qe_identity_issuer_chain": rd("qe_identity_issuer_chain.pem"),
        "pck_crl_issuer_chain": rd("pck_crl_issuer_chain.pem"),
        "pck_crl": rd("pck_crl.der", "rb").hex(), "root_ca_crl": rd("root_ca_crl.der", "rb").hex()})


def installed_version():
    try:
        import dcap_qvl  # noqa: F401
        from importlib.metadata import version
        return version("dcap-qvl")
    except Exception:  # noqa: BLE001
        try:
            import dcap_qvl
            return str(getattr(dcap_qvl, "__version__", "?"))
        except Exception:  # noqa: BLE001
            return None


def claims_of(quote, col_dir, now):
    """dcap-qvl verdict over `quote` -> claims dict; raises on any rejection (message = dcap-qvl's reason)."""
    import dcap_qvl
    col = dcap_qvl.QuoteCollateralV3.from_json(collateral_json(col_dir))
    now = int(time.time() if now is None else now)
    pol = dcap_qvl.QuotePolicy.strict(now)
    for _field, meth in PHALA_FLAGS:
        pol = getattr(pol, meth)(True)
    return json.loads(dcap_qvl.QuoteVerifier().verify_with_policy(bytes(quote), col, now, pol).to_json())


def facts_theirs(c):
    td = (c.get("report") or {}).get("TD10") or {}
    pck = ((c.get("platform") or {}).get("pck")) or {}
    out = {"tcb_status": c["tcb"]["status"], "advisory_ids": sorted(c["tcb"].get("advisory_ids") or []),
           "tcb_eval_data_number": c["tcb"]["eval_data_number"],
           "fmspc": "".join("%02x" % b for b in pck.get("fmspc", [])),
           "tcb_date": ((c.get("platform") or {}).get("tcb_level") or {}).get("tcbDate")}
    for f in ("mr_td", "mr_config_id", "td_attributes", "xfam", "tee_tcb_svn", "report_data"):
        out[f] = td.get(f)
    for i in range(4):
        out["rtmr%d" % i] = td.get("rt_mr%d" % i)
    return out


def facts_ours(r):
    t, b = r.get("tcb") or {}, r.get("body") or {}
    out = {"tcb_status": t.get("status"), "advisory_ids": sorted(t.get("advisory_ids") or []),
           "tcb_eval_data_number": t.get("tcb_eval_data_number"), "fmspc": (t.get("fmspc") or "").lower(), "tcb_date": t.get("tcb_date")}
    for f in ("mr_td", "mr_config_id", "td_attributes", "xfam", "tee_tcb_svn", "report_data", "rtmr0", "rtmr1", "rtmr2", "rtmr3"):
        out[f] = b.get(f)
    return out


def diff(ours, theirs):
    return [k for k in ours if ours[k] != theirs.get(k)]


def run(quotes, col_dir, now):
    """quotes: [(label, raw quote, our tdx_quote.verify result)]. -> dict with state, version, detail line pieces."""
    ver = installed_version()
    if ver is None:
        return {"state": "NOT_INSTALLED", "version": None, "msg": INSTALL}
    if not col_dir:
        return {"state": "NOT_RUN", "version": ver, "msg": "needs --tee-collateral=<dir> (offline: the same Intel collateral as the main check)"}
    bad, flags = [], {}
    for label, q, ours in quotes:
        try:
            c = claims_of(q, col_dir, now)
        except Exception as e:  # noqa: BLE001  (a foreign wheel must never crash the checker)
            bad.append("%s: dcap-qvl rejects (%s)" % (label, str(e)[:160]))
            continue
        pck = ((c.get("platform") or {}).get("pck")) or {}
        for f, _m in PHALA_FLAGS:
            flags[f] = str(pck.get(f)).lower() if f not in flags or flags[f] == str(pck.get(f)).lower() else "mixed"
        d = diff(facts_ours(ours), facts_theirs(c))
        if d:
            bad.append("%s: %s" % (label, ",".join(d)))
    return {"state": "DISAGREE" if bad else "AGREE", "version": ver, "bad": bad, "flags": flags}


def lines(res, strict):
    """-> [(line, makes_pack_invalid)]"""
    name = "tee second verifier (%s %s)" % (NAME, ".".join((res["version"] or "?").split(".")[:2]))
    st = res["state"]
    if st == "NOT_INSTALLED":
        return [("tee second verifier (%s): NOT VERIFIED (%s)" % (NAME, res["msg"]), strict)]
    if st == "NOT_RUN":
        return [("%s: NOT RUN (%s)" % (name, res["msg"]), strict)]
    out = [("%s: policy allows Phala platform flags: %s (seen in the quotes: %s)"
            % (name, ", ".join(m for _f, m in PHALA_FLAGS), ", ".join("%s=%s" % kv for kv in sorted(res["flags"].items())) or "none"), False)]
    if st == "AGREE":
        out.append(("%s: AGREE" % name, False))
    else:
        out.append(("%s: DISAGREE: %s%s" % (name, "; ".join(res["bad"]),
                    "" if strict else " (warning only; add --tee-second-verifier-strict to make it INVALID)"), strict))
    return out
