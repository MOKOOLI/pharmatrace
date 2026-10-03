"""FastAPI layer. Run: uvicorn pharmatrace.api.main:app --reload"""
from __future__ import annotations

import os
from dataclasses import asdict

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, constr

from pharmatrace.core.security import AuthError, Role, TokenSigner, hash_password, verify_password
from pharmatrace.core.service import DomainError, TraceService

app = FastAPI(title="PharmaTrace", version="0.1.0",
              description="Tamper-evident pharmaceutical traceability API")
svc = TraceService(os.getenv("PHARMATRACE_DB", "pharmatrace.db"))
signer = TokenSigner(os.getenv("PHARMATRACE_SECRET"), ttl_seconds=3600)
USERS: dict[str, dict] = {}  # demo user store; swap for a DB table in production


@app.exception_handler(AuthError)
async def _auth(_: Request, exc: AuthError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.exception_handler(DomainError)
async def _domain(_: Request, exc: DomainError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    })
    return resp


def claims(authorization: str = Header(...)) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    try:
        return signer.verify(authorization[7:])
    except AuthError as e:
        raise HTTPException(401, str(e))


Str = constr(strip_whitespace=True, min_length=1, max_length=128)


class SignupIn(BaseModel):
    username: Str
    password: constr(min_length=10, max_length=256)
    role: Role
    org_id: Str


class LoginIn(BaseModel):
    username: Str
    password: str


class DrugIn(BaseModel):
    gtin: constr(pattern=r"^\d{8}$|^\d{12,14}$")
    name: Str


class UnitsIn(BaseModel):
    gtin: constr(pattern=r"^\d{8}$|^\d{12,14}$")
    lot: Str
    expiry: constr(pattern=r"^\d{4}-\d{2}-\d{2}$")
    count: int = Field(ge=1, le=10_000)


class TransferIn(BaseModel):
    to_org: Str


@app.post("/auth/signup", status_code=201)
def signup(body: SignupIn):
    # NOTE: in production, regulator accounts must be provisioned out-of-band, never self-served.
    if body.role == Role.REGULATOR:
        raise HTTPException(403, "regulator accounts are provisioned by admins")
    if body.username in USERS:
        raise HTTPException(409, "username taken")
    USERS[body.username] = {"pw": hash_password(body.password), "role": body.role, "org": body.org_id}
    return {"ok": True}


@app.post("/auth/login")
def login(body: LoginIn):
    u = USERS.get(body.username)
    # same error for unknown user / bad password -> no user enumeration
    if not u or not verify_password(body.password, u["pw"]):
        raise HTTPException(401, "invalid credentials")
    return {"access_token": signer.issue(body.username, u["role"], u["org"]), "token_type": "bearer"}


@app.post("/drugs", status_code=201)
def register_drug(body: DrugIn, c: dict = Depends(claims)):
    svc.register_drug(c, body.gtin, body.name)
    return {"ok": True}


@app.post("/drugs/{gtin}/approve")
def approve(gtin: str, c: dict = Depends(claims)):
    svc.approve_drug(c, gtin)
    return {"ok": True}


@app.post("/units", status_code=201)
def create_units(body: UnitsIn, c: dict = Depends(claims)):
    return {"uids": svc.create_units(c, body.gtin, body.lot, body.expiry, body.count)}


@app.post("/units/{uid}/transfer")
def transfer(uid: str, body: TransferIn, c: dict = Depends(claims)):
    svc.transfer(c, uid, body.to_org)
    return {"ok": True}


@app.post("/units/{uid}/dispense")
def dispense(uid: str, c: dict = Depends(claims)):
    svc.dispense(c, uid)
    return {"ok": True}


@app.get("/units/{uid}/history")
def history(uid: str, c: dict = Depends(claims)):
    return svc.history(c, uid)


@app.get("/verify/{uid}")
def public_verify(uid: str, lat: float | None = None, lon: float | None = None):
    """Public endpoint for patients (scan the QR on the box)."""
    return asdict(svc.verify_unit(uid[:64], lat, lon))


@app.get("/ledger/verify")
def ledger_verify(c: dict = Depends(claims)):
    from pharmatrace.core.security import require
    require(c, "ledger:verify")
    return asdict(svc.ledger.verify())


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/analytics/report")
def analytics_report(c: dict = Depends(claims)):
    """Anomaly report over public scans; consumed by the n8n alert workflow."""
    import pandas as pd

    from pharmatrace.analytics.anomaly import model_scores, rule_flags, unknown_clusters
    from pharmatrace.core.security import require

    require(c, "anomaly:read")
    scans = pd.DataFrame(svc.scans(), columns=["uid", "ts", "lat", "lon"])
    known = {r[0] for r in svc.conn.execute("SELECT uid FROM units")}
    k = scans[scans.uid.isin(known)]
    flags = rule_flags(k) if not k.empty else pd.DataFrame(columns=["uid", "rule", "detail"])
    clusters = unknown_clusters(scans, known)
    suspects = model_scores(k).query("is_anomaly") if not k.empty else pd.DataFrame()
    return {
        "alerts": len(flags) + len(clusters) + len(suspects),
        "rule_flags": flags.to_dict(orient="records"),
        "counterfeit_clusters": clusters.to_dict(orient="records"),
        "model_suspects": suspects.reset_index()[["uid", "anomaly_score"]].to_dict(orient="records") if len(suspects) else [],
    }
