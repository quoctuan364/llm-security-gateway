import datetime
import uuid
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from apps.api.src.core.database import Base


def get_utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


class ApiKeyRecord(Base):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    key_hash = Column(String(64), unique=True, index=True, nullable=False)
    prefix = Column(String(20), nullable=False)
    project_id = Column(String(36), index=True, default="default-project")
    is_active = Column(Boolean, default=True, nullable=False)
    role = Column(String(20), default="client", nullable=False)  # "admin" or "client"
    rate_limit_rpm = Column(Integer, default=60, nullable=False)
    daily_token_budget = Column(Integer, default=100_000, nullable=False)
    used_tokens_today = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=True)


class ProjectRecord(Base):
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    org_id = Column(String(36), default="default-org", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)


class PolicyRuleRecord(Base):
    __tablename__ = "policy_rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)  # PROMPT_INJECTION, PII_LEAK, TOOL_EXEC
    risk_threshold = Column(Float, default=0.7, nullable=False)
    action = Column(String(20), default="BLOCK", nullable=False)  # ALLOW, REDACT, WARN, BLOCK
    is_enabled = Column(Boolean, default=True, nullable=False)
    config_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)


class AuditRecord(Base):
    __tablename__ = "audit_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=get_utc_now, index=True, nullable=False)
    correlation_id = Column(String(64), index=True, nullable=False)
    api_key_id = Column(String(36), index=True, nullable=True)
    client_ip = Column(String(50), nullable=True)
    route = Column(String(100), nullable=False)
    action = Column(String(20), nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    prompt_tokens = Column(Integer, default=0, nullable=False)
    completion_tokens = Column(Integer, default=0, nullable=False)
    detections_json = Column(Text, default="[]", nullable=False)
    prev_hash = Column(String(64), default="", nullable=False)
    current_hash = Column(String(64), nullable=False)
