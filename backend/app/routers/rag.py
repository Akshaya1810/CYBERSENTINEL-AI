from fastapi import APIRouter, Query

from app.security.rag import retrieve_security_context

router = APIRouter(prefix="/api/rag", tags=["local-knowledge"])


@router.get("/search")
def search_security_knowledge(
    q: str = Query(min_length=1, max_length=500),
    top_k: int = Query(default=3, ge=1, le=10),
) -> dict[str, object]:
    """Search local security references, kept separate from incident evidence."""
    return {"query": q, "retrieved_context": retrieve_security_context(q, top_k)}