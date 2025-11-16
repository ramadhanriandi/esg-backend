import os, json, time, hmac, base64, hashlib, logging, uuid, io, csv
from urllib.parse import parse_qs
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

rds = boto3.client("rds-data")
secretsmgr = boto3.client("secretsmanager")
s3 = boto3.client("s3")

DB_CLUSTER_ARN = os.environ["DB_CLUSTER_ARN"]
DB_SECRET_ARN = os.environ["DB_SECRET_ARN"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET_ARN = os.environ["JWT_SECRET_ARN"]
S3_REPORTS_BUCKET = os.environ["S3_REPORTS_BUCKET"]

CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
}

def resp(status, body):
    return {"statusCode": status, "headers": {"Content-Type": "application/json", **CORS}, "body": json.dumps(body)}

def resp_no_content():
    return {"statusCode": 204, "headers": CORS, "body": ""}

def _get_method(event):
    return (event.get("httpMethod") or (event.get("requestContext", {}).get("http") or {}).get("method") or "").upper()

def _get_path(event):
    path = event.get("rawPath") or event.get("path") or "/"
    stage = (event.get("requestContext") or {}).get("stage")
    if stage and stage != "$default" and path.startswith(f"/{stage}/"):
        path = path[len(stage)+1:]
    path = "/" + path.strip("/")
    return "/" if path == "//" else path

_jwt_cache = {"v": None, "ts": 0}

def _get_jwt_secret():
    if _jwt_cache["v"] and time.time() - _jwt_cache["ts"] < 300:
        return _jwt_cache["v"]
    val = secretsmgr.get_secret_value(SecretId=JWT_SECRET_ARN)["SecretString"]
    _jwt_cache.update({"v": val, "ts": time.time()})
    return val

def jwt_verify(token: str) -> dict | None:
    try:
        secret = _get_jwt_secret().encode()
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
        if not hmac.compare_digest(hmac.new(secret, signing_input, hashlib.sha256).digest(), sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode())
        if "exp" in payload and int(time.time()) > int(payload["exp"]):
            return None
        return payload
    except Exception:
        return None

def authz(event):
    hdrs = event.get("headers") or {}
    auth = hdrs.get("authorization") or hdrs.get("Authorization") or ""
    if not auth.startswith("Bearer "): return None
    return jwt_verify(auth[7:])

def _looks_uuid(s: str) -> bool:
    try:
        uuid.UUID(str(s)); return True
    except Exception:
        return False

def sql_params(named: dict | None):
    if not named: return []
    params = []
    for k, v in named.items():
        p = {"name": k}
        if v is None:
            p["value"] = {"isNull": True}
        elif isinstance(v, bool):
            p["value"] = {"booleanValue": v}
        elif isinstance(v, int):
            p["value"] = {"longValue": v}
        elif isinstance(v, float):
            p["value"] = {"doubleValue": v}
        else:
            s = str(v)
            p["value"] = {"stringValue": s}
            if (k.lower().endswith("id") or k.lower() in {"cid","uid","sid","company_id","user_id","site_id"}) and _looks_uuid(s):
                p["typeHint"] = "UUID"
        params.append(p)
    return params

def exec_sql(sql: str, params: dict | None = None, tx: str | None = None):
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(json.dumps({"msg":"sql_exec","tx":bool(tx),"sql":sql,"param_keys":list((params or {}).keys())}))
    kwargs = dict(resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, database=DB_NAME,
                  sql=sql, parameters=sql_params(params))
    if tx: kwargs["transactionId"] = tx
    return rds.execute_statement(**kwargs)

def _cell_value(cell: dict):
    if cell.get("isNull"):
        return None

    for k in ("stringValue", "doubleValue", "longValue", "booleanValue"):
        if k in cell:
            return cell[k]

    if "arrayValue" in cell:
        av = cell["arrayValue"]
        for k in ("stringValues","doubleValues","longValues","booleanValues"):
            if k in av: return av[k]

    return None

def _nearest_nominal_band(it_pct):
    if it_pct is None: return 25
    it = float(it_pct)
    if it < 37.5: return 25
    if it < 62.5: return 50
    if it < 87.5: return 75
    return 100

def _compare(comp: str, obs: float, thr: float) -> bool:
    if comp == "<=": return obs <= thr
    if comp == "<":  return obs <  thr
    if comp == ">=": return obs >= thr
    if comp == ">":  return obs >  thr
    return obs <= thr

def _get_thresholds(company_id, site_id, framework_code):
    # PUE (banded)
    pue = {}
    out = exec_sql(
        "SELECT load_band, severity, comparator, threshold_value "
        "FROM thresholds WHERE company_id=:cid AND site_id=:sid AND framework_code=:fw AND indicator='PUE' "
        "ORDER BY load_band, severity",
        {"cid": company_id, "sid": site_id, "fw": framework_code}
    )
    for r in out.get("records", []):
        band   = _cell_value(r[0])
        sev    = _cell_value(r[1])
        comp   = _cell_value(r[2])
        tval   = float(_cell_value(r[3]))
        if band is None:  # safety; PUE should have band
            continue
        pue.setdefault(int(band), {})[sev] = (comp, tval)

    # WUE/CUE (no band)
    simple = {}
    out2 = exec_sql(
        "SELECT indicator, severity, comparator, threshold_value "
        "FROM thresholds WHERE company_id=:cid AND site_id=:sid AND framework_code=:fw "
        "AND indicator IN ('WUE','CUE') AND load_band IS NULL "
        "ORDER BY indicator, severity",
        {"cid": company_id, "sid": site_id, "fw": framework_code}
    )
    for r in out2.get("records", []):
        ind  = _cell_value(r[0])
        sev  = _cell_value(r[1])
        comp = _cell_value(r[2])
        tval = float(_cell_value(r[3]))
        simple.setdefault(ind, {})[sev] = (comp, tval)

    return {"PUE": pue, **simple}

def _get_metrics(company_id, site_id, ts_from_iso: str, ts_to_iso: str):
    out = exec_sql(
        "SELECT indicator, value, it_load_pct, measured_at "
        "FROM metrics WHERE company_id=:cid AND site_id=:sid "
        "AND measured_at >= CAST(:f AS timestamptz) "
        "AND measured_at <  CAST(:t AS timestamptz) "
        "AND indicator IN ('PUE','WUE','CUE') "
        "ORDER BY measured_at",
        {"cid": company_id, "sid": site_id, "f": ts_from_iso, "t": ts_to_iso}
    )
    rows = []
    for r in out.get("records", []):
        rows.append({
            "indicator": _cell_value(r[0]),
            "value": float(_cell_value(r[1])),
            "it_load_pct": (None if _cell_value(r[2]) is None else float(_cell_value(r[2]))),
            "measured_at": _cell_value(r[3])
        })
    return rows

def _compute_summary(company_id, site_id, framework_code, ts_from_iso, ts_to_iso):
    th = _get_thresholds(company_id, site_id, framework_code)
    metrics = _get_metrics(company_id, site_id, ts_from_iso, ts_to_iso)

    site_meta = _get_site_meta(site_id)
    out = {
        "site": site_meta,
        "framework_code": framework_code,
        "period": {"from": ts_from_iso, "to": ts_to_iso},
        "indicators": {
            "PUE": {"samples":0,"ok":0,"warn":0,"crit":0,"avg":None,"min":None,"max":None},
            "WUE": {"samples":0,"ok":0,"warn":0,"crit":0,"avg":None,"min":None,"max":None},
            "CUE": {"samples":0,"ok":0,"warn":0,"crit":0,"avg":None,"min":None,"max":None}
        }
    }

    sums = {"PUE":0.0,"WUE":0.0,"CUE":0.0}
    for m in metrics:
        ind, val, itp = m["indicator"], m["value"], m["it_load_pct"]
        out["indicators"][ind]["samples"] += 1
        sums[ind] += val
        out["indicators"][ind]["min"] = val if out["indicators"][ind]["min"] is None else min(out["indicators"][ind]["min"], val)
        out["indicators"][ind]["max"] = val if out["indicators"][ind]["max"] is None else max(out["indicators"][ind]["max"], val)

        if ind == "PUE":
            nominal = _nearest_nominal_band(itp)
            pue_map = th.get("PUE", {})
            if not pue_map:
                out["indicators"][ind]["ok"] += 1
                continue
            # choose nearest *defined* band
            bands = list(pue_map.keys())
            chosen = min(bands, key=lambda b: abs(int(b) - nominal))
            warn = pue_map.get(chosen, {}).get("WARN")
            crit = pue_map.get(chosen, {}).get("CRIT")
            state = "OK"
            if crit and not _compare(crit[0], val, crit[1]): state = "CRIT"
            elif warn and not _compare(warn[0], val, warn[1]): state = "WARN"
        else:
            mp = th.get(ind, {})
            warn = mp.get("WARN")
            crit = mp.get("CRIT")
            state = "OK"
            if crit and not _compare(crit[0], val, crit[1]): state = "CRIT"
            elif warn and not _compare(warn[0], val, warn[1]): state = "WARN"

        out["indicators"][ind][state.lower()] += 1

    for ind in ("PUE","WUE","CUE"):
        s = out["indicators"][ind]["samples"]
        if s > 0:
            out["indicators"][ind]["avg"] = round(sums[ind] / s, 6)
            ok = out["indicators"][ind]["ok"]
            out["indicators"][ind]["ok_pct"]   = round(ok / s * 100.0, 2)
            out["indicators"][ind]["warn_pct"] = round(out["indicators"][ind]["warn"] / s * 100.0, 2)
            out["indicators"][ind]["crit_pct"] = round(out["indicators"][ind]["crit"] / s * 100.0, 2)
        else:
            out["indicators"][ind]["ok_pct"] = out["indicators"][ind]["warn_pct"] = out["indicators"][ind]["crit_pct"] = 0.0

    return out

def _summary_to_csv(summary: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    site = summary.get("site", {}) or {}
    w.writerow(["site_name", site.get("name", "")])
    w.writerow(["timezone", site.get("timezone", "")])
    w.writerow(["country", site.get("country", "")])
    w.writerow(["framework_code", summary["framework_code"]])
    w.writerow(["from", summary["period"]["from"]])
    w.writerow(["to", summary["period"]["to"]])
    w.writerow([])
    w.writerow(["indicator","samples","ok","warn","crit","ok_pct","warn_pct","crit_pct","avg","min","max"])
    for ind, d in summary["indicators"].items():
        w.writerow([ind, d["samples"], d["ok"], d["warn"], d["crit"],
                    d.get("ok_pct",0.0), d.get("warn_pct",0.0), d.get("crit_pct",0.0),
                    d["avg"], d["min"], d["max"]])
    return buf.getvalue().encode()

def _slug(s: str) -> str:
    s = (s or "").lower()
    out = []
    for ch in s:
        if ch.isalnum(): out.append(ch)
        elif ch in (" ", "-", "_", "."): out.append("-")
    slug = "".join(out).strip("-")
    while "--" in slug: slug = slug.replace("--", "-")
    return slug or "site"

def _get_site_meta(site_id: str) -> dict:
    out = exec_sql(
        "SELECT name, timezone, country FROM sites WHERE site_id=:sid LIMIT 1",
        {"sid": site_id}
    ).get("records", [])
    if out:
        name = _cell_value(out[0][0]) or site_id
        tz   = _cell_value(out[0][1]) or "UTC"
        ctry = _cell_value(out[0][2]) or "Unknown"
        return {"name": name, "timezone": tz, "country": ctry}

    return {"name": site_id, "timezone": "UTC", "country": "Unknown"}

def post_reports(event, claims):
    body = json.loads(event.get("body") or "{}")

    site_id = (body.get("site_id") or "").strip()
    framework_code = (body.get("framework_code") or "GMDC_SG_2024").strip()
    ts_from = (body.get("from") or "").strip()
    ts_to   = (body.get("to") or "").strip()
    fmt     = (body.get("format") or "json").strip().lower()

    if not site_id or not ts_from or not ts_to:
        return resp(400, {"message":"site_id, from, to required"})

    own = exec_sql("SELECT 1 FROM sites WHERE site_id=:sid AND company_id=:cid LIMIT 1",
                   {"sid": site_id, "cid": claims["company_id"]}).get("records")
    if not own: return resp(404, {"message":"site not found"})

    s = _compute_summary(claims["company_id"], site_id, framework_code, ts_from, ts_to)

    site_row = exec_sql("SELECT name FROM sites WHERE site_id=:sid LIMIT 1", {"sid": site_id}).get("records") or []
    site_name = _cell_value(site_row[0][0]) if site_row else site_id

    def _parse_iso(ts):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            return datetime.strptime(ts, "%Y-%m-%d").replace(tzinfo=timezone.utc)

    dt_from = _parse_iso(ts_from)
    dt_to = _parse_iso(ts_to)
    from_str = dt_from.strftime("%Y-%m-%d")
    to_str = dt_to.strftime("%Y-%m-%d")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    title = f"EcoTrack Report — {site_name} — {framework_code} — {from_str} to {to_str}"

    base_prefix = f"reports/{site_id}/{framework_code}/"
    filename_no_ext = f"ecotrack_report_{_slug(site_name)}_{framework_code}_{from_str}_to_{to_str}_{stamp}"
    if fmt == "csv":
        body_bytes = _summary_to_csv(s)
        key = base_prefix + filename_no_ext + ".csv"
        s3.put_object(Bucket=S3_REPORTS_BUCKET, Key=key, Body=body_bytes, ContentType="text/csv")
        filename = filename_no_ext + ".csv"
    else:
        key = base_prefix + filename_no_ext + ".json"
        s3.put_object(Bucket=S3_REPORTS_BUCKET, Key=key, Body=json.dumps(s).encode(), ContentType="application/json")
        filename = filename_no_ext + ".json"

    url = s3.generate_presigned_url(
        ClientMethod="get_object", Params={"Bucket": S3_REPORTS_BUCKET, "Key": key}, ExpiresIn=3600
    )
    return resp(201, {
        "report_id": str(uuid.uuid4()),   # keep a traceable id if you still want one
        "title": title,
        "filename": filename,
        "s3_key": key,
        "format": fmt,
        "download_url": url
    })

def get_reports_summary(event, claims):
    qs = parse_qs(event.get("rawQueryString") or "")
    site_id = (qs.get("site_id",[None])[0] or "").strip()
    framework_code = (qs.get("framework_code",["GMDC_SG_2024"])[0] or "GMDC_SG_2024").strip()
    ts_from = (qs.get("from",[None])[0] or "").strip()
    ts_to   = (qs.get("to",[None])[0] or "").strip()
    if not site_id or not ts_from or not ts_to:
        return resp(400, {"message":"site_id, from, to required"})

    own = exec_sql("SELECT 1 FROM sites WHERE site_id=:sid AND company_id=:cid LIMIT 1",
                   {"sid": site_id, "cid": claims["company_id"]}).get("records")
    if not own: return resp(404, {"message":"site not found"})

    s = _compute_summary(claims["company_id"], site_id, framework_code, ts_from, ts_to)
    return resp(200, s)

def lambda_handler(event, context):
    method = _get_method(event)
    path = _get_path(event)

    logger.info({"method": method, "path": path, "raw": event})

    if method == "OPTIONS":
        return resp_no_content()

    if path == "/metrics" and method == "POST": return post_metrics(event)

    claims = authz(event)
    if not claims: return resp(401, {"message": "unauthorized"})

    if path == "/reports" and method == "POST": return post_reports(event, claims)
    if path == "/reports/summary" and method == "GET": return get_reports_summary(event, claims)

    return resp(404, {"message":"not found"})
