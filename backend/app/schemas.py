from typing import Literal, Optional

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class AskRequest(BaseModel):
    question: str
    model: Optional[str] = None
    conversation_id: Optional[str] = None


class ContextChunk(BaseModel):
    source: str
    text: str


class AskResponse(BaseModel):
    answer: str
    sources: list[str]
    context_chunks: list[ContextChunk] = []
    model: str
    elapsed_seconds: float
    conversation_id: str
    prompt: Optional[str] = None


class ConversationSummary(BaseModel):
    id: str
    title: str
    author: str
    updated_at: str
    message_count: int


class ConversationDetail(BaseModel):
    id: str
    title: str
    author: str
    created_at: str
    updated_at: str
    messages: list[dict]


class RenameConversationRequest(BaseModel):
    title: str


class UpdateIncidentRequest(BaseModel):
    case_status: Optional[Literal["open", "investigating", "closed"]] = None
    assigned_to: Optional[str] = None
    priority: Optional[int] = None


class NoteRequest(BaseModel):
    text: str


class CloseIncidentRequest(BaseModel):
    resolution: str
    # Required, not optional — this is what guarantees the rule-health rollup and the
    # "seen before" precedent embedding (rag.embed_case_resolution) are only ever built from a
    # real human judgment call, never left to default to nothing. "needs_review" is deliberately
    # excluded here: it's a valid AI verdict but not a valid terminal human disposition.
    disposition: Literal["true_positive", "false_positive", "benign_positive"]


class AWSCredentialsRequest(BaseModel):
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    region: Optional[str] = None


class BedrockCredentialsRequest(BaseModel):
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    region: Optional[str] = None


class BedrockApiKeyRequest(BaseModel):
    api_key: str
    region: Optional[str] = None


class WazuhCredentialsRequest(BaseModel):
    host: str
    user: str
    password: str
    verify_ssl: bool = True


class ThreatIntelCredentialsRequest(BaseModel):
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    abusech_auth_key: Optional[str] = None


class BulkDeleteRequest(BaseModel):
    ids: list[str]


class ExclusionRuleRequest(BaseModel):
    # Plain-language mode: description alone, AI-structured into criteria at save time.
    # Structured mode: any of rule_id/rule_description/ip provided instead — these are combined
    # directly into criteria (AND'd together) with no AI call, for an analyst who wants exact
    # control rather than trusting the model's interpretation. description is still optional
    # in structured mode purely as a human-readable label; one is auto-generated if omitted.
    description: Optional[str] = None
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    ip: Optional[str] = None
    ip_field: Literal["source_ip", "agent.ip"] = "source_ip"


class UpdateExclusionRuleRequest(BaseModel):
    description: Optional[str] = None
    active: Optional[bool] = None


class EnabledSettingRequest(BaseModel):
    """Shared by every pipeline-stage pause toggle (alert ingestion, case correlation,
    AI investigation) — each is just a single on/off switch."""
    enabled: bool


class DefaultAiModelRequest(BaseModel):
    model_config = {"protected_namespaces": ()}  # "model_id" would otherwise warn (pydantic
    # reserves the "model_" prefix for its own use by convention, not a real conflict here)

    # A Bedrock model id, conventionally prefixed "bedrock:" — see rag.py's _generate() for
    # the convention.
    model_id: str


class BudgetCapRequest(BaseModel):
    # None clears the cap (no limit) — same "falsy means unset" convention as the AI model
    # settings above, just a float instead of a string.
    amount: float | None = None


class EvalRunRequest(BaseModel):
    sample_size: int = Field(gt=0, le=200)


class InitUploadRequest(BaseModel):
    filename: str
    total_bytes: int


class DebugModeRequest(BaseModel):
    enabled: bool


class WazuhDiagnosticQueryRequest(BaseModel):
    # GET-only on the backend side regardless of what's typed here — this field only picks
    # which already-configured host (Manager or Indexer) the read-only query runs against.
    target: Literal["manager", "indexer"] = "manager"
    path: str
