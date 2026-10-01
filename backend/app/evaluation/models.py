from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvaluationEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    event_type: str = Field(min_length=1, max_length=100)
    offset_seconds: int = Field(ge=0)
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    description: str = Field(min_length=1)


class VerificationProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    probe_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    claim_type: Literal["fact", "hypothesis"] = "fact"
    event_ids: list[int] = Field(default_factory=list)
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    successful_login: bool | None = None
    expected_status: Literal["supported", "unsupported", "unverified", "contradicted"]


class ResponseConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actions_must_not_execute: bool = True
    high_impact_requires_pending_approval: bool = True
    evidence_ids_must_belong_to_case: bool = True


class SyntheticEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,63}$")
    description: str = Field(min_length=1)
    incident_severity: Literal["Critical", "High", "Medium", "Low"]
    source_ip: str | None = None
    events: list[EvaluationEvent] = Field(min_length=1, max_length=200)
    expected_detection_rules: list[str] = Field(default_factory=list)
    expected_risk_category: Literal["critical", "high", "medium", "low"]
    expected_attack_mappings: list[str] = Field(default_factory=list)
    expected_evidence_ids: list[int] = Field(default_factory=list)
    verification_probes: list[VerificationProbe] = Field(default_factory=list)
    response_constraints: ResponseConstraints = Field(default_factory=ResponseConstraints)
    expected_related_event_groups: list[list[int]] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_and_case_scoped_ids(self):
        event_ids = [event.id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("Event IDs must be unique within a case.")
        if not set(self.expected_evidence_ids) <= set(event_ids):
            raise ValueError("Expected evidence IDs must refer to events in this case.")
        if any(
            not set(probe.event_ids) <= set(event_ids)
            for probe in self.verification_probes
            if probe.expected_status != "unsupported"
        ):
            raise ValueError(
                "Only probes expected to be unsupported may reference absent event IDs."
            )
        if any(
            len(group) < 2 or not set(group) <= set(event_ids)
            for group in self.expected_related_event_groups
        ):
            raise ValueError("Related-event groups need at least two valid case event IDs.")
        return self


class SyntheticEvaluationDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    cases: list[SyntheticEvaluationCase] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_case_ids(self):
        ids = [case.case_id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("Case IDs must be unique within a dataset.")
        event_ids = [
            event.id for case in self.cases for event in case.events
        ]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("Event IDs must be unique across the evaluation dataset.")
        return self
