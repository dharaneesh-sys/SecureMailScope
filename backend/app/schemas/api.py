from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AnalysisOptions(BaseModel):
    detect_smtp: bool = True
    detect_imap: bool = True
    detect_pop3: bool = True
    inspect_tls: bool = True
    inspect_certificates: bool = True
    apply_rules: bool = True
    generate_report: bool = True


class AnalysisCreate(BaseModel):
    capture_id: str = Field(min_length=8, max_length=32, pattern=r"^[0-9a-f]+$")
    authorised_confirmation: bool
    options: AnalysisOptions = AnalysisOptions()


class FindingStatusUpdate(BaseModel):
    status: Literal["open", "under_review", "resolved", "accepted_risk"]
    note: str | None = Field(default=None, max_length=400)


class RuleUpdate(BaseModel):
    enabled: bool


class ReportCreate(BaseModel):
    format: Literal["json", "html", "csv", "pdf"]
