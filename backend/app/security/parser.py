import csv
import ipaddress
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

SSH_FAILED = "ssh_authentication_failed"
SSH_SUCCEEDED = "ssh_authentication_succeeded"
SSH_INVALID_USER = "ssh_invalid_user"
SSH_UNCLASSIFIED = "ssh_unclassified"

SSH_PREFIX_PATTERNS = (
    re.compile(
        r"^(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
        r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s*(?P<message>.*)$"
    ),
    re.compile(
        r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s*(?P<message>.*)$"
    ),
)
SSH_MESSAGE_PATTERN = re.compile(r"sshd(?:\[\d+\])?:\s*(?P<message>.*)$")
SSH_FAILED_PATTERN = re.compile(
    r"^Failed password for (?:(?P<invalid>invalid user)\s+)?(?P<username>\S+) from (?P<ip>\S+)\b"
)
SSH_ACCEPTED_PATTERN = re.compile(
    r"^Accepted password for (?P<username>\S+) from (?P<ip>\S+)\b"
)
SSH_INVALID_PATTERN = re.compile(
    r"^Invalid user (?P<username>\S+) from (?P<ip>\S+)\b"
)
RFC3164_PATTERN = "%b %d %H:%M:%S"


@dataclass(frozen=True)
class ParsedLogRecord:
    event_type: str
    description: str
    timestamp: datetime | None
    source_ip: str | None
    username: str | None
    hostname: str | None
    raw_log: str
    source_line: int


@dataclass(frozen=True)
class ParseIssue:
    record_number: int
    reason: str


@dataclass
class ParseOutput:
    records: list[ParsedLogRecord] = field(default_factory=list)
    malformed: list[ParseIssue] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class LogParseError(ValueError):
    pass


class RecordLimitExceeded(LogParseError):
    pass


def normalize_event_type(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    compact = normalized.replace("_", "")
    if compact in {
        "sshfailedpassword", "failedpassword", "authenticationfailed", "failedsshauthentication",
        "authenticationfailure", "sshauthfailure", "sshlogonfailure", "sshauthenticationfailed",
    }:
        return SSH_FAILED
    if compact in {
        "sshacceptedpassword", "acceptedpassword", "successfulpasswordauthentication",
        "successfulsshlogin", "sshauthenticationaccepted", "sshauthenticationsucceeded",
    }:
        return SSH_SUCCEEDED
    if compact in {"invalidsshuser", "sshinvaliduser", "invaliduser", "invaliduserattempt", "unknownuser"}:
        return SSH_INVALID_USER
    return normalized[:100] or "csv_event"


def _parse_timestamp(value: str, line_number: int, warnings: list[str]) -> datetime:
    stamp = value.strip()
    if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$", stamp):
        parsed = datetime.strptime(f"{datetime.now(timezone.utc).year} {stamp}", f"%Y {RFC3164_PATTERN}")
        warnings.append(f"Record {line_number}: syslog timestamp has no year; current UTC year was assumed.")
        return parsed.replace(tzinfo=timezone.utc)
    if stamp.endswith("Z"):
        stamp = stamp[:-1] + "+00:00"
    parsed = datetime.fromisoformat(stamp)
    if parsed.tzinfo is None:
        warnings.append(f"Record {line_number}: timestamp has no timezone; UTC was assumed.")
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError as error:
        raise LogParseError("Source IP is not a valid IPv4 or IPv6 address.") from error


def _parse_ssh_line(line: str, number: int, warnings: list[str]) -> ParsedLogRecord:
    timestamp: datetime | None = None
    hostname: str | None = None
    message = line.strip()
    for pattern in SSH_PREFIX_PATTERNS:
        match = pattern.match(message)
        if match:
            timestamp = _parse_timestamp(match.group("stamp"), number, warnings)
            hostname = match.group("host")[:255]
            message = match.group("message")
            break
    if timestamp is None:
        ssh_match = SSH_MESSAGE_PATTERN.search(message)
        if ssh_match:
            message = ssh_match.group("message")

    event_type = SSH_UNCLASSIFIED
    username = None
    source_ip = None
    match = SSH_FAILED_PATTERN.match(message)
    if match:
        event_type = SSH_INVALID_USER if match.group("invalid") else SSH_FAILED
        username = match.group("username")
        source_ip = _normalize_ip(match.group("ip"))
    else:
        match = SSH_ACCEPTED_PATTERN.match(message)
        if match:
            event_type = SSH_SUCCEEDED
            username = match.group("username")
            source_ip = _normalize_ip(match.group("ip"))
        else:
            match = SSH_INVALID_PATTERN.match(message)
            if match:
                event_type = SSH_INVALID_USER
                username = match.group("username")
                source_ip = _normalize_ip(match.group("ip"))

    if event_type == SSH_UNCLASSIFIED:
        description = message or line.strip()
    elif event_type == SSH_FAILED:
        description = f"Failed SSH password authentication for username {username}."
    elif event_type == SSH_SUCCEEDED:
        description = f"Successful SSH password authentication for username {username}."
    else:
        description = f"SSH authentication attempt for invalid username {username}."
    return ParsedLogRecord(event_type, description, timestamp, source_ip, username, hostname, line.rstrip("\r\n"), number)


def parse_ssh_text(content: str, max_records: int = 10_000) -> ParseOutput:
    result = ParseOutput()
    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        if len(result.records) + len(result.malformed) >= max_records:
            raise RecordLimitExceeded(f"Upload exceeds the {max_records} record limit.")
        try:
            result.records.append(_parse_ssh_line(line, line_number, result.warnings))
        except (ValueError, OverflowError) as error:
            result.malformed.append(ParseIssue(line_number, str(error) or "Malformed SSH log record."))
    return result


HEADER_ALIASES = {
    "timestamp": {"timestamp", "time", "eventtime", "datetime", "date", "date_time"},
    "event_type": {"eventtype", "event", "eventname", "type", "action"},
    "source_ip": {"sourceip", "srcip", "ip", "remoteip", "clientip", "ipaddress"},
    "username": {"username", "user", "account", "login"},
    "hostname": {"hostname", "host", "device", "system"},
    "description": {"description", "message", "details", "summary"},
    "raw_log": {"rawlog", "raw", "log", "originallog", "rawmessage"},
}


def _canonical_header(value: str) -> str | None:
    compact = re.sub(r"[^a-z0-9]", "", value.strip().lower())
    for canonical, aliases in HEADER_ALIASES.items():
        if compact in {re.sub(r"[^a-z0-9]", "", alias) for alias in aliases}:
            return canonical
    return None


def parse_csv_text(content: str, max_records: int = 10_000) -> ParseOutput:
    result = ParseOutput()
    reader = csv.DictReader(io.StringIO(content, newline=""))
    if not reader.fieldnames:
        raise LogParseError("CSV file is empty or missing a header row.")
    mapped_headers: dict[str, str] = {}
    for header in reader.fieldnames:
        if header and (canonical := _canonical_header(header)) and canonical not in mapped_headers.values():
            mapped_headers[header] = canonical
    if not {"event_type", "description", "raw_log"}.intersection(mapped_headers.values()):
        raise LogParseError("CSV must include an event type, description/message, or raw log column.")

    physical_lines = content.splitlines(keepends=True)
    previous_line = reader.line_num
    record_number = 0
    while True:
        try:
            raw_row = next(reader)
        except StopIteration:
            break
        except csv.Error as error:
            result.malformed.append(ParseIssue(max(reader.line_num, 1), f"Malformed CSV record: {error}"))
            break
        record_number += 1
        if record_number > max_records:
            raise RecordLimitExceeded(f"Upload exceeds the {max_records} record limit.")
        end_line = reader.line_num
        original_row = "".join(physical_lines[previous_line:end_line]).rstrip("\r\n")
        previous_line = end_line
        row = {mapped_headers[key]: (value or "").strip() for key, value in raw_row.items() if key in mapped_headers}
        if not any(row.values()):
            continue
        fallback_raw = row.get("raw_log") or original_row
        line_number = end_line
        raw_for_ssh = row.get("raw_log") or row.get("description") or ""
        parsed_ssh: ParsedLogRecord | None = None
        if raw_for_ssh:
            try:
                candidate = _parse_ssh_line(raw_for_ssh, line_number, result.warnings)
                if candidate.event_type != SSH_UNCLASSIFIED:
                    parsed_ssh = candidate
            except (ValueError, OverflowError):
                parsed_ssh = None
        try:
            timestamp_text = row.get("timestamp", "")
            timestamp = _parse_timestamp(timestamp_text, line_number, result.warnings) if timestamp_text else (parsed_ssh.timestamp if parsed_ssh else None)
            ip_value = row.get("source_ip") or (parsed_ssh.source_ip if parsed_ssh else None)
            source_ip = _normalize_ip(ip_value)
            username = row.get("username") or (parsed_ssh.username if parsed_ssh else None)
            hostname = row.get("hostname") or (parsed_ssh.hostname if parsed_ssh else None)
            type_value = row.get("event_type", "")
            event_type = normalize_event_type(type_value) if type_value else (parsed_ssh.event_type if parsed_ssh else "csv_event")
            description = row.get("description") or (parsed_ssh.description if parsed_ssh else type_value or fallback_raw)
            result.records.append(ParsedLogRecord(
                event_type=event_type,
                description=description,
                timestamp=timestamp,
                source_ip=source_ip,
                username=username[:150] if username else None,
                hostname=hostname[:255] if hostname else None,
                raw_log=row.get("raw_log") or fallback_raw,
                source_line=line_number,
            ))
        except (ValueError, OverflowError, LogParseError) as error:
            result.malformed.append(ParseIssue(line_number, str(error) or "Malformed CSV record."))
    return result


LogFormat = Literal["ssh", "csv"]
