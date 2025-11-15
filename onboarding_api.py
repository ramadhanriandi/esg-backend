import os, json, time, hmac, base64, hashlib, logging, uuid, secrets
import boto3

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

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_json(obj) -> str:
    return b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())

def hash_password(password: str, iterations: int = 210000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)
    return f"pbkdf2${iterations}${b64url(salt)}${b64url(dk)}"

def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = encoded.split("$", 3)
        if algo != "pbkdf2": return False
        iters = int(iters)
        salt = base64.urlsafe_b64decode(salt_b64 + "==")
        expected = base64.urlsafe_b64decode(hash_b64 + "==")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters, dklen=32)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

_jwt_cache = {"v": None, "ts": 0}

def _get_jwt_secret():
    if _jwt_cache["v"] and time.time() - _jwt_cache["ts"] < 300:
        return _jwt_cache["v"]
    val = secretsmgr.get_secret_value(SecretId=JWT_SECRET_ARN)["SecretString"]
    _jwt_cache.update({"v": val, "ts": time.time()})
    return val

def jwt_encode(payload: dict, ttl_seconds: int = 43200) -> str:
    secret = _get_jwt_secret().encode()
    now = int(time.time())
    body = payload.copy()
    body.setdefault("iat", now)
    body.setdefault("exp", now + ttl_seconds)
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{b64url_json(header)}.{b64url_json(body)}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{signing_input.decode()}.{b64url(sig)}"

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
    hdr = event.get("headers") or {}
    auth = hdr.get("authorization") or hdr.get("Authorization") or ""
    if not auth.startswith("Bearer "): return None
    return jwt_verify(auth[7:])

def sql_params(named: dict | None):
    if not named: return []
    params = []
    for k, v in named.items():
        if v is None: params.append({"name": k, "value": {"isNull": True}}); continue
        if isinstance(v, bool): params.append({"name": k, "value": {"booleanValue": v}}); continue
        if isinstance(v, int):  params.append({"name": k, "value": {"longValue": v}}); continue
        params.append({"name": k, "value": {"stringValue": str(v)}})
    return params

def exec_sql(sql: str, params: dict | None = None, tx: str | None = None):
    kwargs = dict(resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, database=DB_NAME,
                  sql=sql, parameters=sql_params(params))
    if tx: kwargs["transactionId"] = tx
    return rds.execute_statement(**kwargs)

def begin_tx():
    out = rds.begin_transaction(resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, database=DB_NAME)
    return out["transactionId"]

def commit_tx(tx):   rds.commit_transaction(resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, transactionId=tx)
def rollback_tx(tx): rds.rollback_transaction(resourceArn=DB_CLUSTER_ARN, secretArn=DB_SECRET_ARN, transactionId=tx)

def post_register(event):
    body = json.loads(event.get("body") or "{}")
    company_name = (body.get("company_name") or "").strip()
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    if not company_name or not email or not password:
        return resp(400, {"message": "company_name, email, password required"})

    q = exec_sql("SELECT 1 FROM users WHERE email=:email LIMIT 1", {"email": email})
    if q.get("records"): return resp(409, {"message": "email already registered"})

    company_id = str(uuid.uuid4()); user_id = str(uuid.uuid4())
    pwhash = hash_password(password)
    tx = begin_tx()
    try:
        exec_sql("INSERT INTO companies(company_id, name) VALUES (CAST(:cid AS uuid), :name)",
                 {"cid": company_id, "name": company_name}, tx)
        exec_sql("INSERT INTO users(user_id, company_id, email, password_hash) VALUES (CAST(:uid AS uuid), CAST(:cid AS uuid), :email, :ph)",
                 {"uid": user_id, "cid": company_id, "email": email, "ph": pwhash}, tx)
        commit_tx(tx)
    except Exception as e:
        try: rollback_tx(tx)
        except: pass
        logger.exception("register_unexpected_error: " + str(e))
        return resp(500, {"message": "registration failed"})

    token = jwt_encode({"user_id": user_id, "company_id": company_id, "email": email}, ttl_seconds=12*3600)
    return resp(201, {"token": token, "company_id": company_id})

def post_login(event):
    body = json.loads(event.get("body") or "{}")
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    if not email or not password:
        return resp(400, {"message": "email, password required"})

    out = exec_sql("SELECT user_id, company_id, password_hash FROM users WHERE email=:email LIMIT 1",
                   {"email": email})
    if not out.get("records"): return resp(401, {"message": "invalid credentials"})
    rec = out["records"][0]
    uid = next(v for k,v in rec[0].items() if k.endswith("Value"))
    cid = next(v for k,v in rec[1].items() if k.endswith("Value"))
    stored = next(v for k,v in rec[2].items() if k.endswith("Value"))
    if not verify_password(password, stored): return resp(401, {"message": "invalid credentials"})

    token = jwt_encode({"user_id": uid, "company_id": cid, "email": email}, ttl_seconds=12*3600)
    return resp(200, {"token": token, "company_id": cid})

def post_sites(event, claims):
    body = json.loads(event.get("body") or "{}")
    name = (body.get("name") or "").strip()
    country = (body.get("country") or "SG").strip()
    timezone = (body.get("timezone") or "Asia/Singapore").strip()
    if not name: return resp(400, {"message": "name required"})

    out = exec_sql("SELECT 1 FROM sites WHERE company_id = CAST(:cid AS uuid) AND name = :n LIMIT 1",
                   {"cid": claims["company_id"], "n": name})
    if out.get("records"): return resp(409, {"message": "site name already exists"})

    sid = str(uuid.uuid4())
    exec_sql("INSERT INTO sites(site_id, company_id, name, country, timezone) VALUES (CAST(:sid AS uuid), CAST(:cid AS uuid), :n, :c, :tz)",
             {"sid": sid, "cid": claims["company_id"], "n": name, "c": country, "tz": timezone})
    return resp(201, {"site_id": sid})

def get_sites(event, claims):
    out = exec_sql("SELECT site_id, name, country, timezone FROM sites WHERE company_id = CAST(:cid AS uuid) ORDER BY created_at DESC",
                   {"cid": claims["company_id"]})
    sites = []
    for rec in out.get("records", []):
        vals = []
        for f in rec:
            for k,v in f.items():
                if k.endswith("Value"): vals.append(v); break
        sites.append({"site_id": vals[0], "name": vals[1], "country": vals[2], "timezone": vals[3]})
    return resp(200, {"sites": sites})

def lambda_handler(event, context):
    method = _get_method(event)
    path = _get_path(event)

    logger.info({"method": method, "path": path, "raw": event})

    if method == "POST" and path == "/auth/register": return post_register(event)
    if method == "POST" and path == "/auth/login":    return post_login(event)

    claims = authz(event)
    if not claims: return resp(401, {"message": "unauthorized"})

    if path == "/sites" and method == "POST": return post_sites(event, claims)
    if path == "/sites" and method == "GET":  return get_sites(event, claims)
    return resp(404, {"message": "not found"})
