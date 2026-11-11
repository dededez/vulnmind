from datetime import datetime
from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field, model_validator


class TargetType(str, Enum):
    REPOSITORY = "repository"
    WEB = "web"
    BOTH = "both"


class Target(BaseModel):
    type: TargetType
    locator: str = Field(min_length=1)

    @model_validator(mode="after")
    def concrete_type(self):
        if self.type == TargetType.BOTH:
            raise ValueError("Each target must be repository or web; use two targets for both")
        return self


class Authorization(BaseModel):
    authorization_source: str = Field(min_length=1)
    approved_by: str = Field(min_length=1)
    starts_at: datetime
    expires_at: datetime
    repository_roots: list[str] = Field(default_factory=list)
    web_origins: list[str] = Field(default_factory=list)
    denied_repository_roots: list[str] = Field(default_factory=list)
    denied_web_origins: list[str] = Field(default_factory=list)
    allowed_web_paths: dict[str, list[str]] = Field(default_factory=dict)
    denied_web_paths: dict[str, list[str]] = Field(default_factory=dict)
    allowed_ip_networks: list[str] = Field(default_factory=list)
    denied_ip_networks: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid_window(self):
        if self.starts_at.utcoffset() is None or self.expires_at.utcoffset() is None:
            raise ValueError("authorization times must include timezone")
        if self.expires_at <= self.starts_at:
            raise ValueError("expires_at must be later than starts_at")
        if not self.authorization_source.strip() or not self.approved_by.strip():
            raise ValueError("authorization source and approver are required")
        for value in (*self.repository_roots, *self.web_origins, *self.denied_repository_roots, *self.denied_web_origins, *self.allowed_ip_networks, *self.denied_ip_networks):
            if not value.strip():
                raise ValueError("scope entries must not be blank")
        return self


class ScanRequest(BaseModel):
    task_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    targets: list[Target] = Field(min_length=1)
    authorization: Authorization


class AgentResult(BaseModel):
    status: Literal["success", "partial", "blocked", "failed"]
    updates: dict = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)
    next_action: str | None = None
    error: str | None = None


class AgentContext(BaseModel):
    task_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    stage: str = Field(min_length=1)
