from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.timestamp_service import issue_demo_timestamp, verify_demo_timestamp

router = APIRouter()


class TimestampIssueRequest(BaseModel):
    message_imprint_sha256: str


class TimestampVerifyRequest(BaseModel):
    token: dict
    expected_imprint_sha256: str


@router.post("/issue")
def issue_timestamp(request: TimestampIssueRequest):
    try:
        return issue_demo_timestamp(request.message_imprint_sha256)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/verify")
def verify_timestamp(request: TimestampVerifyRequest):
    try:
        return verify_demo_timestamp(request.token, request.expected_imprint_sha256)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
