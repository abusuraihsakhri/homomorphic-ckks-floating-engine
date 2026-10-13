"""FastAPI interface for the threshold-evaluation demonstration."""
import hmac
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .base import AuditLogger, SecurityException
from .models import SystemTaskPayload
from .supervisor import SystemSupervisor

supervisor = SystemSupervisor(model_provider="mock")

app = FastAPI(
    title="CKKS-Named Threshold Evaluation Demo",
    description="Rule-based metric evaluation. Does not perform homomorphic encryption.",
    version="3.0.1",
)


class ChatRequest(BaseModel):
    query: str


@app.get("/")
def dashboard():
    return FileResponse(Path(__file__).resolve().parent.parent / "web" / "index.html")


@app.get("/health")
def health():
    return {"status": "HEALTHY", "service": "homomorphic-ckks-floating-engine", "mode": "threshold-evaluation", "version": "3.0.1"}


@app.get("/metrics")
def metrics():
    return {
        "dossiers_processed_total": len(supervisor.dossier_registry),
        "audit_blocks_total": len(AuditLogger.get_trail()),
        "audit_integrity_valid": AuditLogger.verify_integrity(),
    }


@app.post("/api/audit")
def api_audit(payload: SystemTaskPayload):
    try:
        return supervisor.process_task(payload).to_dict()
    except SecurityException as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/chat")
def api_chat(req: ChatRequest):
    try:
        return {"response": supervisor.query_supervisory_chat(req.query)}
    except SecurityException as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/audit/logs")
def api_audit_logs(x_audit_token: Optional[str] = Header(default=None)):
    """Restrict detailed ledger access; no unauthenticated default."""
    configured = os.getenv("AUDIT_API_TOKEN")
    if not configured:
        raise HTTPException(status_code=503, detail="Audit log endpoint is disabled")
    if not x_audit_token or not hmac.compare_digest(x_audit_token, configured):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"audit_trail": AuditLogger.get_trail(), "verified": AuditLogger.verify_integrity()}
