import re
from datetime import datetime, timezone

from siem.utils import LogEvent, parse_timestamp, extract_ips, severity_from_str


SYSLOG_PATTERN = re.compile(
    r"^(?:<(\d+)>)?"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(\S+)"
    r"\s+(\S+?)(?:\[(\d+)\])?:"
    r"\s+(.*)$"
)

WIN_EVT_FWD_PATTERN = re.compile(
    r"^(?:<(\d+)>)?"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(\S+)"
    r"\s+(\S+)\s+(\d+)\s+(\d+)\s+\{(.*?)\}\s+(.*)$"
)

AUTHLOG_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(\S+)"
    r"\s+(\S+):\s+(.*)$"
)

SSH_FAILED_PATTERN = re.compile(
    r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)"
)

SSH_ACCEPTED_PATTERN = re.compile(
    r"Accepted\s+password\s+for\s+(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)"
)

SUDO_PATTERN = re.compile(
    r"sudo:\s+(\S+)\s*:\s+(.+?)\s+(?:for\s+(\S+)\s+)?;\s+(.+?)(?:\s+COMMAND=(.+))?$"
)

APACHE_COMBINED_PATTERN = re.compile(
    r'^(\S+)\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'\[([^\]]+)\]\s+'
    r'"(\S+)\s+(\S+)\s+(\S+)"\s+'
    r'(\d+)\s+'
    r'(\S+)\s+'
    r'"([^"]*)"\s+'
    r'"([^"]*)"$'
)

APACHE_COMMON_PATTERN = re.compile(
    r'^(\S+)\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'\[([^\]]+)\]\s+'
    r'"(\S+)\s+(\S+)\s+(\S+)"\s+'
    r'(\d+)\s+'
    r'(\S+)$'
)

NGINX_ERROR_PATTERN = re.compile(
    r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(\w+)\]\s+"
    r"(\d+)#(\d+):\s+"
    r"\*(?:(\d+))?\s*"
    r"(.*)$"
)

WINDOWS_EVENT_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\d+)\s+"
    r"(\d+)\s+"
    r"(?:\{(.+?)\})?\s*"
    r"(.*)$"
)

FIREWALL_I_PATTERN = re.compile(
    r"IN=(\S+)\s+OUT=(\S*)\s+"
    r"MAC=\S+\s+"
    r"SRC=([\d.]+)\s+DST=([\d.]+)\s+"
    r"LEN=\d+\s+TOS=\S+\s+PREC=\S+\s+"
    r"TTL=\d+\s+ID=\d+\s+"
    r"(?:DF\s+)?PROTO=(\S+)\s+"
    r"SPT=(\d+)\s+DPT=(\d+)"
)

JSON_LOG_PATTERN = re.compile(r"^\{.*\}$")

CSV_DELIM = re.compile(r'[,\t|]')


def parse_log(event: LogEvent) -> LogEvent:
    raw = event.raw

    if JSON_LOG_PATTERN.match(raw):
        return _parse_json_log(event)

    m = APACHE_COMBINED_PATTERN.match(raw)
    if m:
        return _parse_apache_combined(event, m)

    m = APACHE_COMMON_PATTERN.match(raw)
    if m:
        return _parse_apache_common(event, m)

    m = NGINX_ERROR_PATTERN.match(raw)
    if m:
        return _parse_nginx_error(event, m)

    m = AUTHLOG_PATTERN.match(raw)
    if m:
        return _parse_authlog(event, m)

    m = SYSLOG_PATTERN.match(raw)
    if m:
        return _parse_syslog(event, m)

    m = WIN_EVT_FWD_PATTERN.match(raw)
    if m:
        return _parse_win_evt_fwd(event, m)

    m = WINDOWS_EVENT_PATTERN.match(raw)
    if m:
        return _parse_windows_event(event, m)

    m = FIREWALL_I_PATTERN.search(raw)
    if m:
        return _parse_firewall(event, m)

    ips = extract_ips(raw)
    if ips:
        event.src_ip = ips[0]

    return event


def _parse_json_log(event: LogEvent) -> LogEvent:
    import json
    try:
        data = json.loads(event.raw)
        event.normalized = data
        event.message = str(data.get("message", data.get("msg", data.get("event", event.raw))))
        event.host = str(data.get("host", data.get("hostname", data.get("computer", ""))))
        event.service = str(data.get("service", data.get("app", data.get("program", ""))))
        event.level = str(data.get("level", data.get("severity", data.get("lvl", "INFO")))).upper()
        event.src_ip = str(data.get("src_ip", data.get("source_ip", data.get("clientip", ""))))
        event.dst_ip = str(data.get("dst_ip", data.get("dest_ip", "")))
        event.user = str(data.get("user", data.get("username", data.get("userid", ""))))
        event.event_id = str(data.get("event_id", data.get("eid", data.get("id", ""))))
        event.event_type = str(data.get("event_type", data.get("type", data.get("category", ""))))
        event.severity = severity_from_str(event.level)

        ts_str = str(data.get("timestamp", data.get("@timestamp", data.get("time", data.get("date", "")))))
        if ts_str:
            parsed = parse_timestamp(ts_str)
            if parsed:
                event.timestamp = parsed

        event.extra = {k: v for k, v in data.items()
                       if k not in ("message", "host", "service", "level",
                                    "src_ip", "dst_ip", "user", "event_id",
                                    "event_type", "timestamp", "@timestamp",
                                    "time", "date", "msg")}
    except json.JSONDecodeError:
        pass
    return event


def _parse_syslog(event: LogEvent, m: re.Match) -> LogEvent:
    priority = m.group(1)
    ts_str = m.group(2)
    host = m.group(3)
    service = m.group(4)
    pid = m.group(5)
    message = m.group(6)

    event.host = host
    event.service = service
    event.pid = pid or ""
    event.message = message
    event.source = "syslog"

    parsed_ts = parse_timestamp(ts_str)
    if parsed_ts:
        event.timestamp = parsed_ts

    ips = extract_ips(message)
    if ips:
        event.src_ip = ips[0]

    _check_auth_messages(event, message)
    _check_sudo_messages(event, message)

    return event


def _parse_win_evt_fwd(event: LogEvent, m: re.Match) -> LogEvent:
    priority = m.group(1)
    ts_str = m.group(2)
    host = m.group(3)
    source = m.group(4)
    event_id = m.group(5)
    version = m.group(6)
    guid = m.group(7)
    message = m.group(8)

    event.host = host
    event.service = source
    event.event_id = event_id
    event.message = message
    event.source = "win_evt_fwd"

    # event_id-based classification
    if event_id in ("4624",):
        event.event_type = "successful_login"
    elif event_id in ("4625", "4776"):
        event.event_type = "failed_login"
    elif event_id in ("4688",):
        event.event_type = "process_creation"
    elif event_id in ("7045", "4697"):
        event.event_type = "service_installation"
    elif event_id in ("1102", "104"):
        event.event_type = "log_cleared"
        event.severity = max(event.severity, 6)
    elif event_id in ("4104",):
        event.event_type = "powershell"
    elif event_id in ("5156", "5158"):
        event.event_type = "network_connection"

    parsed_ts = parse_timestamp(ts_str)
    if parsed_ts:
        event.timestamp = parsed_ts

    ips = extract_ips(message)
    if ips:
        event.src_ip = ips[0]

    _check_auth_messages(event, message)
    return event


def _parse_authlog(event: LogEvent, m: re.Match) -> LogEvent:
    ts_str = m.group(1)
    host = m.group(2)
    service = m.group(3)
    message = m.group(4)

    event.host = host
    event.service = service
    event.message = message
    event.source = "authlog"

    parsed_ts = parse_timestamp(ts_str)
    if parsed_ts:
        event.timestamp = parsed_ts

    _check_auth_messages(event, message)
    _check_sudo_messages(event, message)
    return event


def _parse_apache_combined(event: LogEvent, m: re.Match) -> LogEvent:
    event.src_ip = m.group(1)
    event.user = m.group(3) if m.group(3) != "-" else ""
    event.method = m.group(5)
    event.path = m.group(6)
    event.protocol = m.group(7)
    try:
        event.status = int(m.group(8))
    except ValueError:
        pass
    try:
        event.size = int(m.group(9)) if m.group(9) != "-" else 0
    except ValueError:
        pass
    event.referer = m.group(10)
    event.user_agent = m.group(11)
    event.service = "apache"
    event.source = "apache"
    event.message = f"{event.method} {event.path} -> {event.status}"

    if event.status >= 500:
        event.severity = max(event.severity, 4)
        event.event_type = "server_error"
    elif event.status == 404:
        event.event_type = "not_found"
    elif event.status == 403:
        event.event_type = "forbidden"
    elif event.status == 401:
        event.event_type = "unauthorized"
    elif event.status >= 400:
        event.event_type = "client_error"

    paths_lower = event.path.lower()
    if any(a in paths_lower for a in ("admin", "wp-admin", "config", "setup", "install")):
        event.tags.append("admin_access_attempt")
    if any(s in paths_lower for s in (".php", ".asp", ".jsp", ".cgi")):
        event.tags.append("dynamic_request")
    return event


def _parse_apache_common(event: LogEvent, m: re.Match) -> LogEvent:
    event.src_ip = m.group(1)
    event.user = m.group(3) if m.group(3) != "-" else ""
    event.method = m.group(5)
    event.path = m.group(6)
    event.protocol = m.group(7)
    try:
        event.status = int(m.group(8))
    except ValueError:
        pass
    try:
        event.size = int(m.group(9)) if m.group(9) != "-" else 0
    except ValueError:
        pass
    event.service = "apache"
    event.source = "apache"
    event.message = f"{event.method} {event.path} -> {event.status}"
    return event


def _parse_nginx_error(event: LogEvent, m: re.Match) -> LogEvent:
    ts_str = m.group(1)
    level = m.group(2)
    pid = m.group(3)
    tid = m.group(4)
    conn_id = m.group(5)
    message = m.group(6)

    event.service = "nginx"
    event.pid = pid
    event.message = message
    event.level = level.upper()
    event.severity = severity_from_str(level)
    event.source = "nginx"

    try:
        event.timestamp = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    return event


def _parse_windows_event(event: LogEvent, m: re.Match) -> LogEvent:
    ts_str = m.group(1)
    host = m.group(2)
    service = m.group(3)
    eid = m.group(4)
    _level = m.group(5)
    _guid = m.group(6)
    message = m.group(7)

    event.host = host
    event.service = service
    event.event_id = eid
    event.message = message
    event.source = "windows"

    parsed_ts = parse_timestamp(ts_str)
    if parsed_ts:
        event.timestamp = parsed_ts

    eid_num = int(eid) if eid.isdigit() else 0
    if eid_num == 4625:
        event.event_type = "failed_login"
        event.severity = max(event.severity, 4)
    elif eid_num == 4624:
        event.event_type = "successful_login"
    elif eid_num == 4648:
        event.event_type = "explicit_credential_use"
    elif eid_num == 4672:
        event.event_type = "admin_logon"
        event.tags.append("privilege_assignment")
    elif eid_num == 4688:
        event.event_type = "process_creation"
        ips = extract_ips(message)
        if ips:
            event.src_ip = ips[0]
    elif eid_num == 7045:
        event.event_type = "service_install"
        event.severity = max(event.severity, 3)
    elif eid_num == 1102:
        event.event_type = "audit_log_cleared"
        event.severity = max(event.severity, 5)
    return event


def _parse_firewall(event: LogEvent, m: re.Match) -> LogEvent:
    event.extra["in_interface"] = m.group(1)
    event.extra["out_interface"] = m.group(2)
    event.src_ip = m.group(3)
    event.dst_ip = m.group(4)
    event.protocol = m.group(5)
    event.src_port = m.group(6)
    event.dst_port = m.group(7)
    event.service = "iptables"
    event.source = "firewall"

    if "DPT=22" in event.raw or "DPT=21" in event.raw or "DPT=23" in event.raw:
        event.event_type = "port_scan"
    elif "INVALID" in event.raw:
        event.event_type = "invalid_packet"
    elif "DROP" in event.raw:
        event.event_type = "dropped_packet"
    return event


def _check_auth_messages(event: LogEvent, message: str) -> None:
    m = SSH_FAILED_PATTERN.search(message)
    if m:
        event.user = m.group(1)
        event.src_ip = m.group(2)
        event.event_type = "failed_login"
        event.service = "sshd"
        event.severity = max(event.severity, 4)
        event.tags.append("ssh_bruteforce")
        return

    m = SSH_ACCEPTED_PATTERN.search(message)
    if m:
        event.user = m.group(1)
        event.src_ip = m.group(2)
        event.event_type = "successful_login"
        event.service = "sshd"
        return

    if "Failed password" in message:
        event.event_type = "failed_login"
        event.severity = max(event.severity, 4)
    elif "Accepted" in message and "password" in message:
        event.event_type = "successful_login"
    elif "Connection closed by authenticating user" in message:
        event.event_type = "auth_timeout"
    elif "Invalid user" in message:
        event.event_type = "invalid_user"
        event.severity = max(event.severity, 3)
    elif "BREAK_IN" in message or "break-in" in message:
        event.event_type = "break_in_attempt"
        event.severity = max(event.severity, 6)
    elif "Connection from" in message and "port" in message:
        ips = extract_ips(message)
        if ips:
            event.src_ip = ips[0]


def _check_sudo_messages(event: LogEvent, message: str) -> None:
    m = SUDO_PATTERN.search(message)
    if m:
        user = m.group(1)
        tty_info = m.group(2)
        target_user = m.group(3) or ""
        command = m.group(5) or m.group(4) or ""

        event.user = user
        event.message = f"sudo: {user} ran '{command}'"
        event.event_type = "privilege_escalation"
        event.tags.append("sudo")
        event.extra["sudo_command"] = command
        event.extra["sudo_target"] = target_user
        event.extra["sudo_tty"] = tty_info
        return

    # Fallback: any sudo message qualifies as privilege_escalation
    if re.search(r'\bsudo\b', message, re.I):
        event.event_type = "privilege_escalation"
        event.tags.append("sudo")
        event.severity = max(event.severity, 3)
