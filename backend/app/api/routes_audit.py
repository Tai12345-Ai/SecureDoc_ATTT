from fastapi import APIRouter
from app.services.audit_service import list_events

router = APIRouter()

@router.get("/events")
def events(limit: int = 20):
    return list_events(limit=limit)
