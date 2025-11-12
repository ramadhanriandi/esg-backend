import os, json, time, hmac, base64, hashlib, logging, uuid
from urllib.parse import parse_qs

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

rds = boto3.client("rds-data")
secretsmgr = boto3.client("secretsmanager")

DB_CLUSTER_ARN = os.environ["DB_CLUSTER_ARN"]
DB_SECRET_ARN = os.environ["DB_SECRET_ARN"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET_ARN = os.environ["JWT_SECRET_ARN"]

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

def begin_tx():
    out = rds.begin_transaction(resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, database=DB_NAME)
    return out["transactionId"]

def commit_tx(tx):   rds.commit_transaction(resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, transactionId=tx)

def rollback_tx(tx): rds.rollback_transaction(resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, transactionId=tx)

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

def get_frameworks(event, claims):
    out = exec_sql(
        "SELECT framework_code, name, version, jurisdiction, notes "
        "FROM frameworks ORDER BY jurisdiction, framework_code"
    )
    items = []
    for r in out.get("records", []):
        vals = [_cell_value(c) for c in r]
        items.append({
            "framework_code": vals[0],
            "name": vals[1],
            "version": vals[2],
            "jurisdiction": vals[3],
            "notes": vals[4],
        })
    return resp(200, {"frameworks": items})

def get_site_frameworks(event, claims):
    qs = parse_qs(event.get("rawQueryString") or "")
    site_id = (qs.get("site_id",[None])[0] or "").strip()
    if not site_id:
        return resp(400, {"message":"site_id required"})
    company_id = claims.get("company_id")
    own = exec_sql("SELECT 1 FROM sites WHERE site_id=:sid AND company_id=:cid LIMIT 1",
                   {"sid": site_id, "cid": company_id}).get("records")
    if not own:
        return resp(404, {"message":"site not found"})

    out = exec_sql(
        "SELECT sf.framework_code, f.name, sf.is_active, sf.precedence "
        "FROM site_frameworks sf "
        "JOIN frameworks f ON f.framework_code = sf.framework_code "
        "WHERE sf.site_id = :sid "
        "ORDER BY sf.precedence ASC, sf.framework_code",
        {"sid": site_id}
    )
    items=[]
    for r in out.get("records", []):
        v = [_cell_value(c) for c in r]
        items.append({
            "framework_code": v[0],
            "framework_name": v[1],
            "is_active": v[2],
            "precedence": v[3]
        })
    return resp(200, {"site_id": site_id, "frameworks": items})

def upsert_threshold(company_id, site_id, framework_code, indicator, comparator, value, severity, load_band, tx):
    where = (
        "site_id=:sid AND company_id=:cid AND framework_code=:fw "
        "AND indicator=:ind AND severity=:sev AND "
        + ("load_band=:band" if load_band is not None else "load_band IS NULL")
    )

    res = exec_sql(
        f"UPDATE thresholds SET comparator=:cmp, threshold_value=:val, updated_at=now() WHERE {where}",
        {"cid": company_id, "sid": site_id, "fw": framework_code, "ind": indicator,
         "sev": severity, "cmp": comparator, "val": float(value), "band": load_band},
        tx
    )
    if res.get("numberOfRecordsUpdated", 0) and res["numberOfRecordsUpdated"] > 0:
        return

    try:
        exec_sql(
            "INSERT INTO thresholds(threshold_id,company_id,site_id,framework_code,indicator,comparator,threshold_value,severity,load_band) "
            "VALUES (:tid,:cid,:sid,:fw,:ind,:cmp,:val,:sev,:band)",
            {"tid": str(uuid.uuid4()), "cid": company_id, "sid": site_id, "fw": framework_code,
             "ind": indicator, "cmp": comparator, "val": float(value), "sev": severity, "band": load_band},
            tx
        )
    except ClientError as e:
        err = e.response.get("Error", {})
        msg = (err.get("Message") or "")
        if "23505" in msg or "duplicate key value violates unique constraint" in msg:
            exec_sql(
                f"UPDATE thresholds SET comparator=:cmp, threshold_value=:val, updated_at=now() WHERE {where}",
                {"cid": company_id, "sid": site_id, "fw": framework_code, "ind": indicator,
                 "sev": severity, "cmp": comparator, "val": float(value), "band": load_band},
                tx
            )
        else:
            raise

def post_site_frameworks(event, claims):
    body = json.loads(event.get("body") or "{}")
    site_id = (body.get("site_id") or "").strip()
    if not site_id:
        return resp(400, {"message": "site_id required"})

    company_id = claims.get("company_id")
    own = exec_sql("SELECT 1 FROM sites WHERE site_id=:sid AND company_id=:cid LIMIT 1",
                   {"sid": site_id, "cid": company_id}).get("records")
    if not own:
        return resp(404, {"message": "site not found"})

    if isinstance(body.get("assignments"), list):
        assigns = body["assignments"]
        if not assigns:
            # empty list = deactivate all current assignments for this site
            exec_sql("UPDATE site_frameworks SET is_active=FALSE WHERE site_id=:sid",
                     {"sid": site_id})
            return resp_no_content()

        # Validate all framework codes exist
        codes = [ (a.get("framework_code") or "").strip() for a in assigns ]
        if not all(codes):
            return resp(400, {"message": "every assignment requires framework_code"})
        placeholders = ", ".join([f":fw{i}" for i in range(len(codes))])
        params = {f"fw{i}": codes[i] for i in range(len(codes))}
        exists = exec_sql(f"SELECT framework_code FROM frameworks WHERE framework_code IN ({placeholders})", params)
        existing_codes = { _cell_value(r[0]) for r in (exists.get("records") or []) }
        missing = [c for c in codes if c not in existing_codes]
        if missing:
            return resp(400, {"message": "unknown framework_code", "details": missing})

        # Transaction: upsert provided, deactivate missing
        tx = begin_tx()
        try:
            # 1) Upsert each provided assignment
            for a in assigns:
                fw = (a.get("framework_code") or "").strip()
                is_active = bool(a.get("is_active", True))
                precedence = int(a.get("precedence", 100))
                # UPDATE first
                res = rds.execute_statement(
                    resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, database=DB_NAME,
                    transactionId=tx,
                    sql=("UPDATE site_frameworks SET is_active=:act, precedence=:pre "
                         "WHERE site_id=:sid AND framework_code=:fw"),
                    parameters=sql_params({"sid": site_id, "fw": fw, "act": is_active, "pre": precedence})
                )
                if res.get("numberOfRecordsUpdated", 0) == 0:
                    # INSERT if missing
                    rds.execute_statement(
                        resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, database=DB_NAME,
                        transactionId=tx,
                        sql=("INSERT INTO site_frameworks(site_id, framework_code, is_active, precedence) "
                             "VALUES (:sid, :fw, :act, :pre)"),
                        parameters=sql_params({"sid": site_id, "fw": fw, "act": is_active, "pre": precedence})
                    )

            # 2) Deactivate any currently assigned frameworks NOT in the list
            placeholders = ", ".join([f":fw{i}" for i in range(len(codes))])
            params = {"sid": site_id, **{f"fw{i}": codes[i] for i in range(len(codes))}}
            rds.execute_statement(
                resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, database=DB_NAME,
                transactionId=tx,
                sql=(f"UPDATE site_frameworks SET is_active=FALSE "
                     f"WHERE site_id=:sid AND framework_code NOT IN ({placeholders})"),
                parameters=sql_params(params)
            )

            commit_tx(tx)
            return resp_no_content()
        except Exception:
            try: rollback_tx(tx)
            except Exception: pass
            logger.exception("site_frameworks_sync_error")
            return resp(500, {"message": "failed to sync site frameworks"})

    return resp_no_content()

def post_thresholds(event, claims):
    body = json.loads(event.get("body") or "{}")
    site_id = (body.get("site_id") or "").strip()
    framework_code = (body.get("framework_code") or "GMDC_SG_2024").strip()
    rules = body.get("rules") or []

    if not site_id or not isinstance(rules, list) or not rules:
        logger.warning(json.dumps({"msg":"bad_request_thresholds"}))
        return resp(400, {"message": "site_id and rules[] required"})

    fw_ok = exec_sql("SELECT 1 FROM frameworks WHERE framework_code=:fw LIMIT 1",
                     {"fw": framework_code}).get("records")
    if not fw_ok:
        return resp(400, {"message": "unknown framework_code"})

    company_id = claims["company_id"]
    own = exec_sql("SELECT 1 FROM sites WHERE site_id=:sid AND company_id=:cid LIMIT 1",
                   {"sid": site_id, "cid": company_id}).get("records")
    if not own:
        return resp(404, {"message":"site not found"})

    tx = begin_tx()
    try:
        for r in rules:
            indicator = (r.get("indicator") or "").upper()
            comparator = (r.get("comparator") or "")
            severity = (r.get("severity") or "").upper()
            value = r.get("value")
            load_band = r.get("load_band")
            remove = bool(r.get("remove", False))

            if indicator not in ("PUE","WUE","CUE") or severity not in ("WARN","CRIT") or comparator not in ("<=",">=","<",">"):
                return resp(400, {"message":"invalid rule"})
            try:
                if isinstance(value, str): float(value)
                elif isinstance(value, (int,float)): float(value)
                else: return resp(400, {"message":"value must be numeric"})
            except Exception:
                return resp(400, {"message":"value must be numeric"})

            if indicator == "PUE":
                if load_band not in (25,50,75,100):
                    return resp(400, {"message":"load_band must be 25/50/75/100 for PUE"})
            else:
                if load_band is not None:
                    return resp(400, {"message":"WUE/CUE must not have load_band"})

            if remove:
                if indicator == "PUE":
                    exec_sql(
                        "DELETE FROM thresholds WHERE company_id=:cid AND site_id=:sid AND framework_code=:fw "
                        "AND indicator='PUE' AND load_band=:band AND severity=:sev",
                        {"cid": company_id, "sid": site_id, "fw": framework_code,
                        "band": int(load_band), "sev": severity},
                        tx
                    )
                else:
                    exec_sql(
                        "DELETE FROM thresholds WHERE company_id=:cid AND site_id=:sid AND framework_code=:fw "
                        "AND indicator=:ind AND load_band IS NULL AND severity=:sev",
                        {"cid": company_id, "sid": site_id, "fw": framework_code,
                        "ind": indicator, "sev": severity},
                        tx
                    )
            else:
                upsert_threshold(company_id, site_id, framework_code, indicator, comparator, value, severity, load_band, tx)
        commit_tx(tx)
        logger.info(json.dumps({"msg":"thresholds_upsert_ok","site_id":site_id,"framework_code":framework_code,"count":len(rules)}))
        return resp_no_content()
    except Exception:
        try: rollback_tx(tx)
        except Exception: pass
        logger.exception("thresholds_upsert_error")
        return resp(500, {"message":"failed to save thresholds"})

def get_thresholds(event, claims):
    qs = parse_qs(event.get("rawQueryString") or "")
    site_id = (qs.get("site_id",[None])[0] or "").strip()
    framework_code = (qs.get("framework_code",["GMDC_SG_2024"])[0] or "GMDC_SG_2024").strip()
    if not site_id:
        return resp(400, {"message":"site_id required"})

    company_id = claims["company_id"]
    own = exec_sql("SELECT 1 FROM sites WHERE site_id=:sid AND company_id=:cid LIMIT 1",
                   {"sid": site_id, "cid": company_id}).get("records")
    if not own:
        return resp(404, {"message":"site not found"})

    out = exec_sql(
      "SELECT indicator, comparator, threshold_value, severity, load_band "
      "FROM thresholds WHERE company_id=:cid AND site_id=:sid AND framework_code=:fw "
      "ORDER BY indicator, COALESCE(load_band,0), severity",
      {"cid": company_id, "sid": site_id, "fw": framework_code}
    )

    rules = []
    for rec in out.get("records", []):
        vals = [_cell_value(f) for f in rec]  # always length == number of selected columns
        rules.append({
            "indicator":   vals[0],
            "comparator":  vals[1],
            "value":       float(vals[2]),
            "severity":    vals[3],
            "load_band":   vals[4]  # may be None for WUE/CUE rows
        })
    return resp(200, {"site_id": site_id, "framework_code": framework_code, "rules": rules})

def get_alerts(event, claims):
    qs = parse_qs(event.get("rawQueryString") or "")
    status = (qs.get("status",["OPEN"])[0] or "OPEN").upper()
    framework_code = (qs.get("framework_code",["GMDC_SG_2024"])[0] or "GMDC_SG_2024").strip()
    site_id = (qs.get("site_id",[None])[0] or "").strip()
    if status not in ("OPEN","CLEARED"):
        return resp(400, {"message":"status must be OPEN or CLEARED"})

    company_id = claims["company_id"]
    sql = ("SELECT alert_id, site_id, indicator, severity, comparator, threshold_value, observed_value, status, raised_at, cleared_at "
           "FROM alerts WHERE company_id=:cid AND framework_code=:fw AND status=:st")
    params = {"cid": company_id, "fw": framework_code, "st": status}
    if site_id:
        own = exec_sql("SELECT 1 FROM sites WHERE site_id=:sid AND company_id=:cid LIMIT 1",
                       {"sid": site_id, "cid": company_id}).get("records")
        if not own:
            return resp(404, {"message":"site not found"})
        sql += " AND site_id=:sid"; params["sid"] = site_id
    sql += " ORDER BY raised_at DESC LIMIT 200"

    out = exec_sql(sql, params)
    
    alerts = []
    for rec in out.get("records", []):
        vals = [_cell_value(f) for f in rec]
        alerts.append({
            "alert_id":        vals[0],
            "site_id":         vals[1],
            "indicator":       vals[2],
            "severity":        vals[3],
            "comparator":      vals[4],
            "threshold_value": float(vals[5]),
            "observed_value":  float(vals[6]),
            "status":          vals[7],
            "raised_at":       vals[8],
            "cleared_at":      vals[9]
        })
    return resp(200, {"alerts": alerts})

def lambda_handler(event, context):
    method = _get_method(event)
    path = _get_path(event)

    logger.info({"method": method, "path": path, "raw": event})

    if method == "OPTIONS":
        return resp_no_content()

    claims = authz(event)
    if not claims: return resp(401, {"message": "unauthorized"})

    if path == "/frameworks" and method == "GET": return get_frameworks(event, claims)
    if path == "/site_frameworks" and method == "GET": return get_site_frameworks(event, claims)
    if path == "/site_frameworks" and method == "POST": return post_site_frameworks(event, claims)
    if path == "/thresholds" and method == "POST": return post_thresholds(event, claims)
    if path == "/thresholds" and method == "GET": return get_thresholds(event, claims)
    if path == "/alerts" and method == "GET": return get_alerts(event, claims)

    return resp(404, {"message":"not found"})
