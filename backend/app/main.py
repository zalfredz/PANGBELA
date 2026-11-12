import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import db
from app.api import incidents, ingest, patches, recommendations, tests_api
from app.config import settings
from app.runner import Runner, recover_stale_runs


@asynccontextmanager
async def lifespan(_: FastAPI):
    recover_stale_runs()
    runner = Runner(settings)
    task = asyncio.create_task(runner.loop())
    yield
    task.cancel()
    runner.shutdown()


app = FastAPI(title="ai-soc", lifespan=lifespan)
app.include_router(ingest.router)
app.include_router(incidents.router)
app.include_router(recommendations.router)
app.include_router(tests_api.router)
app.include_router(patches.router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Section 8: every error body is {"error", "detail"}, not FastAPI's default {"detail"}.
@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict):  # raised through app.api.errors.api_error
        content = exc.detail
    else:  # raised by FastAPI itself, such as 404 for an unknown route
        code = str(exc.detail).lower().replace(" ", "_")
        content = {"error": code, "detail": str(exc.detail)}
    return JSONResponse(status_code=exc.status_code, content=content)


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    # Location and message only; echoing the rejected input back could reflect a payload.
    detail = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
    return JSONResponse(status_code=422, content={"error": "invalid_request", "detail": detail})


@app.get("/health")
def health() -> JSONResponse:
    try:
        with db.connect() as conn:
            conn.execute(text("SELECT 1"))
    except SQLAlchemyError as e:
        return JSONResponse(
            status_code=503,
            content={"error": "db_unavailable", "detail": type(e).__name__},
        )
    return JSONResponse({"db": "ok", "llm_configured": settings.llm_configured})
