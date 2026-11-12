from fastapi import HTTPException


def api_error(status: int, code: str, detail: str) -> HTTPException:
    """An error in the section 8 shape: {"error": code, "detail": detail}."""
    return HTTPException(status, {"error": code, "detail": detail})
