import os, json, time, hmac, base64, hashlib, logging, uuid, secrets
import boto3, os

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

rds = boto3.client("rds-data")
secretsmgr = boto3.client("secretsmanager")
ses = boto3.client("sesv2", region_name=os.environ.get("SES_REGION", "ap-southeast-1"))

DB_CLUSTER_ARN = os.environ["DB_CLUSTER_ARN"]
DB_SECRET_ARN = os.environ["DB_SECRET_ARN"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET_ARN = os.environ["JWT_SECRET_ARN"]
SENDER = os.environ.get("ALERT_EMAIL_SENDER")
RECEIVER = os.environ.get("ALERT_EMAIL_RECEIVER")

CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Api-Key",
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

def _hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()

def authz_ingest_token(event):
    hdrs = event.get("headers") or {}
    token = hdrs.get("x-api-key") or hdrs.get("X-Api-Key")
    if not token:
        auth = hdrs.get("authorization") or hdrs.get("Authorization") or ""
        if auth.startswith("Ingest "): token = auth[7:]
    if not token: return None

    h = _hash_token(token)
    out = exec_sql(
        "SELECT token_id, company_id, user_id FROM ingest_tokens WHERE token_hash=:h AND active=TRUE LIMIT 1",
        {"h": h}
    )
    recs = out.get("records") or []
    if not recs: return None
    vals = [_cell_value(c) for c in recs[0]]
    
    try: exec_sql("UPDATE ingest_tokens SET last_used_at=now() WHERE token_id=:tid", {"tid": vals[0]})
    except Exception: pass
    return {"token_id": vals[0], "company_id": vals[1], "user_id": vals[2]}

def _nearest_band(it_pct: float | None) -> int:
    if it_pct is None: return 25
    bands = [25,50,75,100]
    return min(bands, key=lambda b: abs(b - float(it_pct)))

def _compare(comparator: str, observed: float, threshold: float) -> bool:
    if comparator == "<=": return observed <= threshold
    if comparator == "<":  return observed <  threshold
    if comparator == ">=": return observed >= threshold
    if comparator == ">":  return observed >  threshold
    return observed <= threshold

def _get_company_user_email(company_id: str) -> str | None:
    out = exec_sql("SELECT email FROM users WHERE company_id=:cid LIMIT 1", {"cid": company_id})
    recs = out.get("records") or []
    return _cell_value(recs[0][0]) if recs else None

def _get_site_name(site_id: str) -> str:
    out = exec_sql("SELECT name FROM sites WHERE site_id=:sid LIMIT 1", {"sid": site_id})
    recs = out.get("records") or []
    return _cell_value(recs[0][0]) if recs else site_id

def _send_alert_email(to_email: str, subject: str, html: str, text: str):
    if not (to_email and SENDER): 
        return
    to_email = RECEIVER # override to fixed receiver for testing
    ses.send_email(
        FromEmailAddress=SENDER,
        Destination={"ToAddresses": [to_email]},
        Content={
            "Simple": {
                "Subject": {"Data": subject},
                "Body": {
                    "Text": {"Data": text},
                    "Html": {"Data": html}
                }
            }
        }
    )
    logger.info(json.dumps({"msg":"send_alert_email", "sender": SENDER, "receiver": to_email}))

def _open_or_update_alert(company_id, site_id, framework_code, indicator, new_sev, comp, thr_val, observed):
    rec = exec_sql(
        "SELECT alert_id, severity FROM alerts "
        "WHERE company_id=:cid AND site_id=:sid AND framework_code=:fw AND indicator=:ind AND status='OPEN' "
        "LIMIT 1",
        {"cid": company_id, "sid": site_id, "fw": framework_code, "ind": indicator}
    ).get("records", [])

    prev_sev = _cell_value(rec[0][1]) if rec else None
    action = None  # "OPENED" | "ESCALATED" | "RESOLVED" | None

    # Decide action & write
    if new_sev:  # we have a breach
        if not rec:
            # INSERT OPEN
            exec_sql(
                "INSERT INTO alerts(alert_id,company_id,site_id,framework_code,indicator,severity,comparator,threshold_value,observed_value,status,raised_at) "
                "VALUES (:aid,:cid,:sid,:fw,:ind,:sev,:cmp,:thr,:obs,'OPEN',now())",
                {"aid": str(uuid.uuid4()), "cid": company_id, "sid": site_id, "fw": framework_code,
                 "ind": indicator, "sev": new_sev, "cmp": comp, "thr": float(thr_val), "obs": float(observed)}
            )
            action = "OPENED"
        else:
            # UPDATE existing; detect escalation (WARN -> CRIT)
            if prev_sev != new_sev:
                action = "ESCALATED" if (prev_sev == "WARN" and new_sev == "CRIT") else None
            exec_sql(
                "UPDATE alerts SET severity=:sev, comparator=:cmp, threshold_value=:thr, observed_value=:obs "
                "WHERE alert_id=:aid",
                {"sev": new_sev, "cmp": comp, "thr": float(thr_val), "obs": float(observed),
                 "aid": _cell_value(rec[0][0])}
            )
    else:
        # No breach -> close if open
        if rec:
            exec_sql("UPDATE alerts SET status='CLEARED', cleared_at=now() WHERE alert_id=:aid",
                     {"aid": _cell_value(rec[0][0])})
            action = "RESOLVED"

    # Send e-mail if there was a notable transition
    if action in ("OPENED", "ESCALATED", "RESOLVED"):
        to_email = _get_company_user_email(company_id)
        site_name = _get_site_name(site_id)
        subj = f"[EcoTrack] {action}: {indicator} @ {site_name} ({framework_code})"
        text = (
            f"Action: {action}\n"
            f"Indicator: {indicator}\n"
            f"Framework: {framework_code}\n"
            f"Site: {site_name}\n"
            f"Observed: {observed}\n"
            f"Threshold: {comp} {thr_val}\n"
        )
        html = f"""
        <h3>EcoTrack Alert: {action}</h3>
        <p><b>Indicator:</b> {indicator}<br/>
           <b>Framework:</b> {framework_code}<br/>
           <b>Site:</b> {site_name}<br/>
           <b>Observed:</b> {observed} &nbsp;&nbsp; <b>Threshold:</b> {comp} {thr_val}</p>
        <p>This message was generated automatically by EcoTrack.</p>
        """
        try:
            _send_alert_email(to_email, subj, html, text)
        except Exception:
            logger.exception("alert_email_send_failed")

def _evaluate_one(company_id, site_id, indicator, observed, it_load_pct):
    out_fw = exec_sql(
        "SELECT f.framework_code FROM site_frameworks sf "
        "JOIN frameworks f ON f.framework_code=sf.framework_code "
        "WHERE sf.site_id=:sid AND sf.is_active=TRUE ORDER BY sf.precedence ASC",
        {"sid": site_id}
    )
    frameworks = [ _cell_value(r[0]) for r in out_fw.get("records", []) ] or ["GMDC_SG_2024"]

    for fw in frameworks:
        logger.info(json.dumps({"msg":"eval_begin", "framework": fw, "indicator": indicator,
                                "it_band": _nearest_band(it_load_pct) if indicator=="PUE" else None,
                                "observed": observed}))

        if indicator == "PUE":
            band = _nearest_band(it_load_pct)
            logger.info(json.dumps({"msg":"eval_thresholds_searching",
                                "company_id": company_id, "site_id": site_id, "indicator": indicator,
                                "framework_code": fw, "load_band": band}))
            out_thr = exec_sql(
                "SELECT comparator, threshold_value, severity FROM thresholds "
                "WHERE company_id=:cid AND site_id=:sid AND framework_code=:fw "
                "AND indicator='PUE' AND load_band=:band",
                {"cid": company_id, "sid": site_id, "fw": fw, "band": band}
            ).get("records", [])
        else:
            logger.info(json.dumps({"msg":"eval_thresholds_searching",
                                "company_id": company_id, "site_id": site_id, "indicator": indicator,
                                "framework_code": fw}))
            out_thr = exec_sql(
                "SELECT comparator, threshold_value, severity FROM thresholds "
                "WHERE company_id=:cid AND site_id=:sid AND framework_code=:fw "
                "AND indicator=:ind AND load_band IS NULL",
                {"cid": company_id, "sid": site_id, "fw": fw, "ind": indicator}
            ).get("records", [])

        logger.info(json.dumps({"msg":"eval_thresholds_matched",
                                "framework": fw, "indicator": indicator,
                                "rows": len(out_thr)}))

        crit = warn = None
        for row in out_thr:
            comp = _cell_value(row[0]); tval = float(_cell_value(row[1])); sev = _cell_value(row[2])
            breach = not _compare(comp, observed, tval)
            if sev == "CRIT" and breach: crit = (comp, tval)
            if sev == "WARN" and breach: warn = (comp, tval)

        if crit:
            comp, tval = crit
            logger.info(json.dumps({"msg":"alert_eval","state":"CRIT",
                                    "framework": fw, "indicator": indicator,
                                    "observed": observed, "comp": comp, "thr": tval}))
            _open_or_update_alert(company_id, site_id, fw, indicator, "CRIT", comp, tval, observed)
        elif warn:
            comp, tval = warn
            logger.info(json.dumps({"msg":"alert_eval","state":"WARN",
                                    "framework": fw, "indicator": indicator,
                                    "observed": observed, "comp": comp, "thr": tval}))
            _open_or_update_alert(company_id, site_id, fw, indicator, "WARN", comp, tval, observed)
        else:
            logger.info(json.dumps({"msg":"alert_eval","state":"OK",
                                    "framework": fw, "indicator": indicator,
                                    "observed": observed}))
            # Clear any open alert for this framework+indicator
            _open_or_update_alert(company_id, site_id, fw, indicator, None, "<=", 0.0, observed)

def post_ingest_tokens(event, claims):
    body   = json.loads(event.get("body") or "{}")
    company_id = claims.get("company_id")
    user_id    = claims.get("user_id")
    if not company_id or not user_id:
        return resp(401, {"message":"unauthorized"})
    name = (body.get("name") or "").strip() or "default"

    exec_sql("UPDATE ingest_tokens SET active=FALSE WHERE user_id=:uid AND active=TRUE",
             {"uid": user_id})

    plain    = base64.urlsafe_b64encode(secrets.token_bytes(24)).rstrip(b"=").decode()
    tok_id   = str(uuid.uuid4())
    tok_hash = hashlib.sha256(plain.encode()).hexdigest()

    exec_sql(
        "INSERT INTO ingest_tokens(token_id,company_id,user_id,name,token_hash,active) "
        "VALUES (:tid,:cid,:uid,:nm,:h,TRUE)",
        {"tid": tok_id, "cid": company_id, "uid": user_id, "nm": name, "h": tok_hash}
    )
    logger.info(json.dumps({"msg":"ingest_token_created","token_id":tok_id,"company_id":company_id,"user_id":user_id}))
    return resp(201, {"token_id": tok_id, "token": plain, "name": name})

def get_ingest_tokens(event, claims):
    company_id = claims.get("company_id")
    user_id    = claims.get("user_id")
    if not company_id or not user_id:
        return resp(401, {"message":"unauthorized"})

    out = exec_sql(
        "SELECT token_id, name, active, created_at, last_used_at "
        "FROM ingest_tokens WHERE company_id=:cid AND user_id=:uid ORDER BY created_at DESC",
        {"cid": company_id, "uid": user_id}
    )
    items=[]
    for r in out.get("records", []):
        vals = [_cell_value(c) for c in r]
        items.append({
            "token_id": vals[0],
            "name": vals[1],
            "active": vals[2],
            "created_at": vals[3],
            "last_used_at": vals[4]
        })
    return resp(200, {"tokens": items})

def post_metrics(event):
    tok = authz_ingest_token(event)
    if not tok:
        return resp(401, {"message":"unauthorized"})

    body = json.loads(event.get("body") or "{}")
    site_id = (body.get("site_id") or "").strip()
    if not site_id:
        return resp(400, {"message":"site_id required"})

    own = exec_sql("SELECT 1 FROM sites WHERE site_id=:sid AND company_id=:cid LIMIT 1",
                   {"sid": site_id, "cid": tok["company_id"]}).get("records")
    if not own:
        return resp(404, {"message":"site not found"})

    measured_at = (body.get("measured_at") or "")
    if measured_at:
        try:
            time.strptime(measured_at.replace("Z","+0000").replace(":","",2), "%Y-%m-%dT%H%M%S%z")
        except Exception:
            return resp(400, {"message":"measured_at must be RFC3339 (e.g., 2025-11-09T10:00:00Z)"})
    else:
        measured_at = None

    it_load_pct = body.get("it_load_pct")
    if it_load_pct is not None:
        try: it_load_pct = float(it_load_pct)
        except Exception: return resp(400, {"message":"it_load_pct must be numeric"})

    measurements = body.get("measurements") or []
    if not isinstance(measurements, list) or not measurements:
        return resp(400, {"message":"measurements[] required"})

    tx = begin_tx()
    try:
        for m in measurements:
            indicator = (m.get("indicator") or "").upper()
            value = m.get("value")
            if indicator not in ("PUE","WUE","CUE"):
                return resp(400, {"message":"indicator must be one of PUE,WUE,CUE"})
            try: value = float(value)
            except Exception: return resp(400, {"message":"value must be numeric"})

            if measured_at:
                load_band = it_load_pct
                if indicator != "PUE":
                    load_band = None
                exec_sql(
                    "INSERT INTO metrics(measurement_id,company_id,site_id,indicator,value,it_load_pct,measured_at) "
                    "VALUES (:mid,:cid,:sid,:ind,:val,:il,CAST(:ts AS timestamptz)) "
                    "ON CONFLICT (site_id,indicator,measured_at) DO UPDATE SET "
                    "  value=EXCLUDED.value, it_load_pct=EXCLUDED.it_load_pct, updated_at=now()",
                    {"mid": str(uuid.uuid4()), "cid": tok["company_id"], "sid": site_id,
                    "ind": indicator, "val": value, "il": load_band, "ts": measured_at},
                    tx
                )
            else:
                exec_sql(
                    "INSERT INTO metrics(measurement_id,company_id,site_id,indicator,value,it_load_pct,measured_at) "
                    "VALUES (:mid,:cid,:sid,:ind,:val,:il, now()) "
                    "ON CONFLICT (site_id,indicator,measured_at) DO UPDATE SET "
                    "  value=EXCLUDED.value, it_load_pct=EXCLUDED.it_load_pct, updated_at=now()",
                    {"mid": str(uuid.uuid4()), "cid": tok["company_id"], "sid": site_id,
                     "ind": indicator, "val": value, "il": it_load_pct},
                    tx
                )

            _evaluate_one(tok["company_id"], site_id, indicator, value, it_load_pct)

        commit_tx(tx)
    except Exception:
        try: rollback_tx(tx)
        except Exception: pass
        logger.exception("metrics_ingest_error")
        return resp(500, {"message":"failed to ingest metrics"})

    return resp(200, {"site_id": site_id, "ingested": len(measurements)})

def lambda_handler(event, context):
    method = _get_method(event)
    path = _get_path(event)

    logger.info({"method": method, "path": path, "raw": event})

    if method == "OPTIONS":
        return resp_no_content()

    if path == "/metrics" and method == "POST": return post_metrics(event)

    claims = authz(event)
    if not claims: return resp(401, {"message": "unauthorized"})

    if path == "/ingest_tokens" and method == "POST": return post_ingest_tokens(event, claims)
    if path == "/ingest_tokens" and method == "GET": return get_ingest_tokens(event, claims)

    return resp(404, {"message":"not found"})
