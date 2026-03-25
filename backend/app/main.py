"""
AI Secure Data Intelligence Platform — FastAPI Application.
Entry point with CORS, request tracing, and health check.
"""

import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.analyze import router as analyze_router
from app.core.config import settings
from app.core.logging_config import generate_request_id, logger, request_id_var
from app.services.honeypot import HoneypotService
from app.services.digital_twin import DigitalTwin
from pydantic import BaseModel

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Modular security analysis platform with AI-enhanced insights. "
        "Ingests multi-source data, detects sensitive information, "
        "analyzes logs, scores risk, and generates actionable insights."
    ),
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request Tracing Middleware ────────────────────────────────────────────────
@app.middleware("http")
async def request_tracing(request: Request, call_next):
    """Add request ID and timing to every request."""
    req_id = generate_request_id()
    request_id_var.set(req_id)
    start = time.time()

    logger.info(f"→ {request.method} {request.url.path}")

    response = await call_next(request)

    duration_ms = (time.time() - start) * 1000
    logger.info(
        f"← {request.method} {request.url.path} "
        f"status={response.status_code} duration={duration_ms:.1f}ms"
    )

    response.headers["X-Request-ID"] = req_id
    return response


# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(analyze_router, tags=["Analysis"])

# ── New Feature Services ──────────────────────────────────────────────────────
honeypot_service = HoneypotService()
digital_twin = DigitalTwin()

class HoneypotRequest(BaseModel):
    target_type: str = "login"
    asset_name: str = "CorpNet"

@app.post("/api/honeypot")
async def generate_honeypot(req: HoneypotRequest):
    result = await honeypot_service.generate(req.target_type, req.asset_name)
    return result

class TwinRequest(BaseModel):
    attack_types: list[str] | None = None

@app.post("/api/twin/simulate")
async def simulate_twin(req: TwinRequest):
    result = digital_twin.simulate(req.attack_types)
    return result


# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "endpoints": {
            "analyze": "POST /analyze",
            "health": "GET /health",
            "honeypot": "POST /api/honeypot",
            "twin": "POST /api/twin/simulate",
        },
    }
