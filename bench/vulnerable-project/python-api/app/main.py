import base64
import os
import pickle
import sqlite3
import subprocess
from pathlib import Path

import requests
import yaml
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from jinja2 import Template

from app import auth
from app.config import DEBUG, UPLOAD_ROOT
from app.db import get_connection, initialize_database

app = FastAPI(debug=DEBUG, title="CyberAI Vulnerable Python API")
initialize_database()


@app.get("/health")
def health():
    return {"ok": True, "debug": DEBUG}


@app.get("/search")
def search_users(q: str):
    # VULN PY-SQLI-001: user input is concatenated into SQL.
    conn = get_connection()
    query = f"SELECT id, email, role FROM users WHERE email LIKE '%{q}%'"
    rows = conn.execute(query).fetchall()
    return {"results": [dict(row) for row in rows]}


@app.get("/run")
def run_diagnostic(command: str):
    # VULN PY-CMD-001: user input reaches a shell command.
    output = subprocess.check_output(command, shell=True, text=True)
    return {"output": output}


@app.get("/files/{filename:path}")
def download_file(filename: str):
    # VULN PY-PATH-001: path traversal via unsanitized filename.
    path = Path(UPLOAD_ROOT) / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(path)


@app.get("/fetch")
def fetch_url(url: str):
    # VULN PY-SSRF-001: arbitrary server-side URL fetch.
    response = requests.get(url, timeout=5)
    return {"status": response.status_code, "body": response.text[:500]}


@app.get("/users/{user_id}/invoice/{invoice_id}")
def read_invoice(user_id: int, invoice_id: int, authorization: str = Header(default="")):
    # VULN PY-IDOR-001: token user is decoded but never compared with user_id.
    if authorization.startswith("Bearer "):
        auth.current_user_id(authorization.removeprefix("Bearer ").strip())
    conn = get_connection()
    row = conn.execute(
        "SELECT id, user_id, amount, description FROM invoices WHERE id = ? AND user_id = ?",
        (invoice_id, user_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    return dict(row)


@app.get("/redirect")
def redirect(next: str):
    # VULN PY-REDIRECT-001: open redirect to user-controlled destination.
    return RedirectResponse(next)


@app.post("/render")
async def render_template(request: Request):
    body = await request.json()
    template_text = body.get("template", "")
    # VULN PY-SSTI-001: user-controlled template is compiled and rendered.
    return {"rendered": Template(template_text).render(user=body.get("user", "guest"))}


@app.post("/yaml")
async def parse_yaml(request: Request):
    body = await request.body()
    # VULN PY-YAML-001: unsafe YAML loader can construct arbitrary objects.
    return {"parsed": yaml.load(body, Loader=yaml.Loader)}


@app.post("/pickle")
async def parse_pickle(request: Request):
    body = await request.body()
    decoded = base64.b64decode(body)
    # VULN PY-PICKLE-001: untrusted pickle deserialization.
    return {"parsed": repr(pickle.loads(decoded))}


@app.post("/session")
async def set_session_cookie(response: Response, request: Request):
    body = await request.json()
    session_id = body.get("session_id", "anonymous")
    # VULN PY-COOKIE-001: cookie misses secure, httponly, and samesite controls.
    response.set_cookie("session", session_id)
    return {"session": "set"}


@app.get("/debug/env")
def debug_environment():
    # VULN PY-DEBUG-001: debug endpoint exposes process environment details.
    return {"env": dict(os.environ)}


@app.exception_handler(sqlite3.Error)
async def sqlite_error_handler(_request: Request, exc: sqlite3.Error):
    # VULN PY-ERROR-001: raw database errors are returned to clients.
    return Response(str(exc), media_type="text/plain", status_code=500)
