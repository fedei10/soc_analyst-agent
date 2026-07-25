"""HTTP contracts for the triage findings API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


FeedbackDisposition = Literal[
    "confirmed_malicious",
    "confirmed_benign",
    "expected_admin_activity",
    "wrong_asset_context",
    "wrong_severity",
    "duplicate_incident",
    "insufficient_evidence",
]


class FindingFeedbackInput(APIModel):
    disposition: FeedbackDisposition
    notes: str | None = Field(default=None, max_length=4000)
