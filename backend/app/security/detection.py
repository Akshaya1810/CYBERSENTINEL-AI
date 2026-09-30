from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from app.core.config import Settings
from app.models.enums import IncidentSeverity
from app.security.parser import SSH_FAILED, SSH_INVALID_USER, SSH_SUCCEEDED

BRUTE_FORCE_RULE_ID = "SSH-AUTH-001"
SUCCESS_AFTER_FAILURES_RULE_ID = "SSH-AUTH-002"
INVALID_USER_RULE_ID = "SSH-AUTH-003"


@dataclass(frozen=True)
class DetectionEvent:
    id: int
    event_type: str
    timestamp: datetime | None
    source_ip: str | None
    username: str | None
    raw_log: str | None


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    name: str
    severity: IncidentSeverity
    threshold: int
    window_seconds: int
    description: str


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    name: str
    severity: IncidentSeverity
    source_ip: str
    description: str
    event_ids: tuple[int, ...]
    triggering_event_ids: tuple[int, ...]


def active_rules(settings: Settings) -> list[RuleDefinition]:
    return [
        RuleDefinition(
            BRUTE_FORCE_RULE_ID,
            "SSH brute-force attempt",
            IncidentSeverity.HIGH,
            settings.ssh_bruteforce_threshold,
            settings.ssh_bruteforce_window_seconds,
            "Repeated failed SSH password authentications from one source IP.",
        ),
        RuleDefinition(
            SUCCESS_AFTER_FAILURES_RULE_ID,
            "Successful SSH login following repeated failures",
            IncidentSeverity.CRITICAL,
            settings.ssh_success_failure_threshold,
            settings.ssh_success_failure_window_seconds,
            "A successful SSH password authentication followed repeated failures from the same source IP.",
        ),
        RuleDefinition(
            INVALID_USER_RULE_ID,
            "Repeated invalid SSH user attempts",
            IncidentSeverity.MEDIUM,
            settings.ssh_invalid_user_threshold,
            settings.ssh_invalid_user_window_seconds,
            "Repeated attempts to authenticate as nonexistent usernames from one source IP.",
        ),
    ]


def detect(events: Iterable[DetectionEvent], new_event_ids: set[int], settings: Settings) -> list[RuleMatch]:
    """Evaluate normalized events only; this module performs no I/O or database work."""
    available = [event for event in events if event.timestamp is not None and event.source_ip]
    by_ip: dict[str, list[DetectionEvent]] = {}
    for event in available:
        by_ip.setdefault(event.source_ip or "", []).append(event)
    matches: list[RuleMatch] = []

    for source_ip, ip_events in by_ip.items():
        failed = sorted(
            (event for event in ip_events if event.event_type in {SSH_FAILED, SSH_INVALID_USER}),
            key=lambda item: item.timestamp or datetime.min,
        )
        qualified_brute: list[tuple[datetime, list[DetectionEvent]]] = []
        brute_window = timedelta(seconds=settings.ssh_bruteforce_window_seconds)
        for trigger in failed:
            trigger_time = trigger.timestamp
            assert trigger_time is not None
            window = [event for event in failed if trigger_time - brute_window <= event.timestamp <= trigger_time]
            new_triggers = [event for event in window if event.id in new_event_ids]
            if len(window) >= settings.ssh_bruteforce_threshold and new_triggers:
                qualified_brute.append((trigger_time, window))
        if qualified_brute:
            _, window = qualified_brute[-1]
            trigger_ids = tuple(event.id for event in window if event.id in new_event_ids)
            matches.append(RuleMatch(
                BRUTE_FORCE_RULE_ID,
                "SSH brute-force attempt",
                IncidentSeverity.HIGH,
                source_ip,
                f"Observed {len(window)} failed SSH password authentications from {source_ip} within {settings.ssh_bruteforce_window_seconds // 60} minutes. This behavior matches a brute-force pattern; it does not establish that the source is malicious or that an account was compromised.",
                tuple(sorted(event.id for event in window)),
                trigger_ids,
            ))

        successful = sorted((event for event in ip_events if event.event_type == SSH_SUCCEEDED), key=lambda item: item.timestamp or datetime.min)
        failure_window = timedelta(seconds=settings.ssh_success_failure_window_seconds)
        qualified_success: list[tuple[datetime, list[DetectionEvent], DetectionEvent]] = []
        for login in successful:
            if login.id not in new_event_ids or login.timestamp is None:
                continue
            preceding = [
                event for event in failed
                if login.timestamp - failure_window <= event.timestamp < login.timestamp
            ]
            if len(preceding) >= settings.ssh_success_failure_threshold:
                qualified_success.append((login.timestamp, preceding, login))
        if qualified_success:
            _, preceding, login = qualified_success[-1]
            matches.append(RuleMatch(
                SUCCESS_AFTER_FAILURES_RULE_ID,
                "Successful SSH login following repeated failures",
                IncidentSeverity.CRITICAL,
                source_ip,
                f"Observed a successful SSH password authentication for {login.username or 'an unspecified username'} from {source_ip} after {len(preceding)} failed attempts within {settings.ssh_success_failure_window_seconds // 60} minutes. This sequence warrants review but alone does not confirm account compromise.",
                tuple(sorted({event.id for event in preceding} | {login.id})),
                (login.id,),
            ))

        invalid = sorted((event for event in ip_events if event.event_type == SSH_INVALID_USER), key=lambda item: item.timestamp or datetime.min)
        invalid_window = timedelta(seconds=settings.ssh_invalid_user_window_seconds)
        qualified_invalid: list[tuple[datetime, list[DetectionEvent]]] = []
        for trigger in invalid:
            trigger_time = trigger.timestamp
            assert trigger_time is not None
            window = [event for event in invalid if trigger_time - invalid_window <= event.timestamp <= trigger_time]
            if len(window) >= settings.ssh_invalid_user_threshold and any(event.id in new_event_ids for event in window):
                qualified_invalid.append((trigger_time, window))
        if qualified_invalid:
            _, window = qualified_invalid[-1]
            users = sorted({event.username for event in window if event.username})
            user_summary = ", ".join(users[:8]) if users else "unspecified usernames"
            matches.append(RuleMatch(
                INVALID_USER_RULE_ID,
                "Repeated invalid SSH user attempts",
                IncidentSeverity.MEDIUM,
                source_ip,
                f"Observed {len(window)} SSH attempts for invalid usernames from {source_ip} within {settings.ssh_invalid_user_window_seconds // 60} minutes ({user_summary}). This is suspicious authentication activity, not proof of compromise.",
                tuple(sorted(event.id for event in window)),
                tuple(event.id for event in window if event.id in new_event_ids),
            ))

    return matches
