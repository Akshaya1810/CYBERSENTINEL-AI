from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import get_settings
from app.db.session import Base, engine
from app.models import Incident, InvestigationResult, SecurityEvent  # Register model metadata.
from app.models import DetectionRecord
from app.routers.detections import MAX_UPLOAD_BYTES, router as detections_router
from app.routers.evaluation import router as evaluation_router
from app.routers.incidents import router as incidents_router
from app.routers.investigations import router as investigations_router
from app.routers.reports import router as reports_router
from app.routers.rag import router as rag_router

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "postgresql":
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE security_events ALTER COLUMN incident_id DROP NOT NULL"))
            connection.execute(text("ALTER TABLE security_events ALTER COLUMN timestamp DROP NOT NULL"))
            connection.execute(text("ALTER TABLE security_events ADD COLUMN IF NOT EXISTS username VARCHAR(150)"))
            connection.execute(text("ALTER TABLE security_events ADD COLUMN IF NOT EXISTS hostname VARCHAR(255)"))
    yield


app = FastAPI(title=settings.app_name, version="0.2.0", lifespan=lifespan)
app.include_router(incidents_router)
app.include_router(investigations_router)
app.include_router(detections_router)
app.include_router(reports_router)
app.include_router(rag_router)
app.include_router(evaluation_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)


@app.middleware("http")
async def limit_log_upload_request(request: Request, call_next):
    if request.method == "POST" and request.url.path == "/api/logs/upload":
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdecimal() and int(content_length) > MAX_UPLOAD_BYTES + 64 * 1024:
            return JSONResponse(status_code=413, content={"detail": "Log upload exceeds the 5 MiB size limit."})
    return await call_next(request)


@app.exception_handler(SQLAlchemyError)
async def database_error_handler(_: Request, __: SQLAlchemyError) -> JSONResponse:
    """Return a safe database error without exposing driver details or credentials."""
    return JSONResponse(
        status_code=503,
        content={"detail": "A database operation failed."},
    )


@app.get("/api/health", tags=["health"])
def health() -> dict[str, str]:
    """Report API process health; this does not test database or AI services."""
    return {"status": "ok", "service": "CyberSentinel AI API"}


@app.get("/api/db-health", tags=["health"], response_model=None)
def database_health() -> dict[str, str] | JSONResponse:
    """Check PostgreSQL connectivity without returning connection details."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except SQLAlchemyError:
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "database": "unavailable",
                "message": "PostgreSQL connection failed. Check backend/.env and confirm the database is running.",
            },
        )
