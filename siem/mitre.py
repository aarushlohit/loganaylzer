from typing import Optional


MITRE_ATTACK = {
    "initial_access": {
        "id": "TA0001",
        "name": "Initial Access",
        "techniques": {
            "T1078": "Valid Accounts",
            "T1190": "Exploit Public-Facing Application",
            "T1133": "External Remote Services",
            "T1566": "Phishing",
            "T1091": "Replication Through Removable Media",
            "T1189": "Drive-by Compromise",
        }
    },
    "execution": {
        "id": "TA0002",
        "name": "Execution",
        "techniques": {
            "T1059": "Command and Scripting Interpreter",
            "T1204": "User Execution",
            "T1047": "Windows Management Instrumentation",
            "T1053": "Scheduled Task/Job",
            "T1106": "Native API",
        }
    },
    "persistence": {
        "id": "TA0003",
        "name": "Persistence",
        "techniques": {
            "T1098": "Account Manipulation",
            "T1136": "Create Account",
            "T1543": "Create or Modify System Process",
            "T1547": "Boot or Logon Autostart Execution",
            "T1505": "Server Software Component",
            "T1053": "Scheduled Task/Job",
        }
    },
    "privilege_escalation": {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "techniques": {
            "T1548": "Abuse Elevation Control Mechanism",
            "T1055": "Process Injection",
            "T1543": "Create or Modify System Process",
            "T1078": "Valid Accounts",
            "T1484": "Domain Policy Modification",
        }
    },
    "defense_evasion": {
        "id": "TA0005",
        "name": "Defense Evasion",
        "techniques": {
            "T1562": "Impair Defenses",
            "T1070": "Indicator Removal on Host",
            "T1036": "Masquerading",
            "T1055": "Process Injection",
            "T1027": "Obfuscated Files or Information",
            "T1112": "Modify Registry",
        }
    },
    "credential_access": {
        "id": "TA0006",
        "name": "Credential Access",
        "techniques": {
            "T1110": "Brute Force",
            "T1552": "Unsecured Credentials",
            "T1555": "Credentials from Password Stores",
            "T1003": "OS Credential Dumping",
            "T1056": "Input Capture",
            "T1558": "Steal or Forge Kerberos Tickets",
        }
    },
    "discovery": {
        "id": "TA0007",
        "name": "Discovery",
        "techniques": {
            "T1087": "Account Discovery",
            "T1069": "Permission Groups Discovery",
            "T1083": "File and Directory Discovery",
            "T1046": "Network Service Discovery",
            "T1135": "Network Share Discovery",
            "T1016": "System Network Configuration Discovery",
            "T1033": "System Owner/User Discovery",
            "T1057": "Process Discovery",
        }
    },
    "lateral_movement": {
        "id": "TA0008",
        "name": "Lateral Movement",
        "techniques": {
            "T1021": "Remote Services",
            "T1570": "Lateral Tool Transfer",
            "T1550": "Use Alternate Authentication Material",
            "T1210": "Exploitation of Remote Services",
            "T1080": "Taint Shared Content",
        }
    },
    "collection": {
        "id": "TA0009",
        "name": "Collection",
        "techniques": {
            "T1005": "Data from Local System",
            "T1039": "Data from Network Shared Drive",
            "T1074": "Data Staged",
            "T1114": "Email Collection",
            "T1056": "Input Capture",
            "T1560": "Archive Collected Data",
        }
    },
    "exfiltration": {
        "id": "TA0010",
        "name": "Exfiltration",
        "techniques": {
            "T1041": "Exfiltration Over C2 Channel",
            "T1567": "Exfiltration Over Web Service",
            "T1029": "Scheduled Transfer",
            "T1537": "Transfer Data to Cloud Account",
            "T1052": "Exfiltration Over Physical Medium",
        }
    },
    "command_and_control": {
        "id": "TA0011",
        "name": "Command and Control",
        "techniques": {
            "T1071": "Application Layer Protocol",
            "T1095": "Non-Application Layer Protocol",
            "T1573": "Encrypted Channel",
            "T1008": "Fallback Channels",
            "T1105": "Ingress Tool Transfer",
            "T1572": "Protocol Tunneling",
        }
    },
    "impact": {
        "id": "TA0040",
        "name": "Impact",
        "techniques": {
            "T1485": "Data Destruction",
            "T1486": "Data Encrypted for Impact",
            "T1565": "Data Manipulation",
            "T1490": "Inhibit System Recovery",
            "T1499": "Endpoint Denial of Service",
            "T1529": "System Shutdown/Reboot",
        }
    },
    "resource_development": {
        "id": "TA0042",
        "name": "Resource Development",
        "techniques": {
            "T1583": "Acquire Infrastructure",
            "T1588": "Obtain Capabilities",
            "T1587": "Develop Capabilities",
            "T1608": "Stage Capabilities",
            "T1584": "Compromise Infrastructure",
        }
    },
}

EVENT_TYPE_TO_MITRE = {
    "failed_login": ("TA0006", "T1110"),
    "brute_force": ("TA0006", "T1110"),
    "successful_login": ("TA0001", "T1078"),
    "privilege_escalation": ("TA0004", "T1548"),
    "sudo_usage": ("TA0004", "T1548"),
    "service_install": ("TA0003", "T1543"),
    "process_creation": ("TA0002", "T1059"),
    "audit_log_cleared": ("TA0005", "T1070"),
    "admin_logon": ("TA0004", "T1078"),
    "port_scan": ("TA0043", "T1046"),
    "exploit_attempt": ("TA0001", "T1190"),
    "web_attack": ("TA0001", "T1190"),
    "data_exfiltration": ("TA0010", "T1041"),
    "command_control": ("TA0011", "T1071"),
    "malware_detected": ("TA0005", "T1562"),
    "break_in_attempt": ("TA0001", "T1190"),
}


def get_mitre_info(event_type: str) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    mapping = EVENT_TYPE_TO_MITRE.get(event_type)
    if not mapping:
        return None, None, None, None

    tactic_id, technique_id = mapping
    tactic_info = None
    technique_name = None

    for tactic_name, tactic_data in MITRE_ATTACK.items():
        if tactic_data["id"] == tactic_id:
            tactic_info = tactic_data["name"]
            if technique_id in tactic_data["techniques"]:
                technique_name = tactic_data["techniques"][technique_id]
            break

    return tactic_id, tactic_info, technique_id, technique_name


def get_tactics_summary() -> dict:
    return {
        name: {
            "id": data["id"],
            "technique_count": len(data["techniques"]),
            "techniques": data["techniques"],
        }
        for name, data in MITRE_ATTACK.items()
    }


ALL_INDICATORS_OF_COMPROMISE: dict[str, list[str]] = {
    "TA0001_initial_access": [
        "unusual_external_connections", "phishing_indicators", "exploit_attempts",
        "drive_by_downloads", "watering_hole_access",
    ],
    "TA0002_execution": [
        "unexpected_process_spawn", "script_execution", "macro_execution",
        "scheduled_task_creation", "wmi_execution",
    ],
    "TA0003_persistence": [
        "new_user_accounts", "registry_run_keys", "startup_folder_modifications",
        "scheduled_tasks", "service_installations", "dll_hijacking",
    ],
    "TA0004_privilege_escalation": [
        "sudoauth_failures", "token_manipulation", "kernel_exploit_attempts",
        "bypass_uac_attempts", "process_injection",
    ],
    "TA0005_defense_evasion": [
        "event_log_cleared", "firewall_disabled", "av_disabled",
        "code_signing_bypass", "file_deletion", "timestomping",
    ],
    "TA0006_credential_access": [
        "brute_force_attempts", "credential_dumping", "keylogger_detected",
        "pass_the_hash", "kerberoasting",
    ],
    "TA0007_discovery": [
        "network_scanning", "account_enumeration", "directory_listing",
        "system_information_gathering", "permission_discovery",
    ],
    "TA0008_lateral_movement": [
        "rdp_connections", "psExec_usage", "wmi_connections",
        "remote_service_creation", "pass_the_ticket",
    ],
    "TA0009_collection": [
        "large_file_access", "screen_capture", "clipboard_access",
        "email_collection", "database_queries",
    ],
    "TA0010_exfiltration": [
        "large_outbound_transfers", "dns_tunneling", "unusual_outbound_ports",
        "compressed_data_transfer", "cloud_api_uploads",
    ],
    "TA0011_command_and_control": [
        "beaconing_traffic", "dns_queries_to_unusual_domains",
        "unusual_protocols", "encrypted_tunnels", "http_https_anomalies",
    ],
}

COMPROMISE_ASSESSMENT_QUESTIONS = {
    "initial_access": "Was there evidence of initial compromise vector?",
    "execution": "Was code executed on the target?",
    "persistence": "Did the attacker establish persistence?",
    "privilege_escalation": "Was privilege escalation achieved?",
    "defense_evasion": "Were defenses evaded or disabled?",
    "credential_access": "Were credentials accessed or stolen?",
    "discovery": "Did the attacker perform discovery?",
    "lateral_movement": "Was lateral movement detected?",
    "collection": "Was data collected?",
    "command_and_control": "Was C2 communication established?",
    "exfiltration": "Was data exfiltrated?",
    "impact": "Was there tangible impact on the organization?",
}


def assess_compromise(triggered_tactics: set[str]) -> dict:
    score = 0
    max_score = len(COMPROMISE_ASSESSMENT_QUESTIONS)
    details: dict[str, bool] = {}

    for tactic, question in COMPROMISE_ASSESSMENT_QUESTIONS.items():
        triggered = tactic.upper().replace(" ", "_") in triggered_tactics
        if triggered:
            score += 1
        details[tactic] = triggered

    confidence = (score / max_score * 100) if max_score > 0 else 0

    if confidence >= 80:
        severity = "CRITICAL"
    elif confidence >= 60:
        severity = "HIGH"
    elif confidence >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "compromise_score": score,
        "max_score": max_score,
        "confidence_percent": round(confidence, 1),
        "severity": severity,
        "details": details,
        "assessment": (
            "Confirmed compromise — multiple attack stages detected"
            if confidence >= 80 else
            "Suspicious activity detected — possible compromise"
            if confidence >= 40 else
            "Low confidence — isolated indicators, further investigation required"
        ),
    }
