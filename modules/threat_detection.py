def detect_threat(event_id):

    threats = {

        4624: {
            "name": "Successful Login",
            "severity": "Low",
            "icon": "🟢",
            "category": "Authentication",
            "description": "User logged in successfully.",
            "mitre_id": "T1078",
            "mitre_tactic": "Initial Access / Persistence — Valid Accounts"
        },

        4625: {
            "name": "Failed Login",
            "severity": "Medium",
            "icon": "🟠",
            "category": "Authentication",
            "description": "Failed user login attempt.",
            "mitre_id": "T1110",
            "mitre_tactic": "Credential Access — Brute Force"
        },

        4672: {
            "name": "Administrator Privilege Assigned",
            "severity": "High",
            "icon": "🔴",
            "category": "Privilege",
            "description": "Administrative privileges assigned after login.",
            "mitre_id": "T1078.003",
            "mitre_tactic": "Privilege Escalation — Valid Accounts: Local Accounts"
        },

        4688: {
            "name": "Process Created",
            "severity": "Medium",
            "icon": "🟠",
            "category": "Process",
            "description": "A new process was created.",
            "mitre_id": "T1059",
            "mitre_tactic": "Execution — Command and Scripting Interpreter"
        },

        4720: {
            "name": "User Account Created",
            "severity": "High",
            "icon": "🔴",
            "category": "Account Management",
            "description": "A new user account was created.",
            "mitre_id": "T1136",
            "mitre_tactic": "Persistence — Create Account"
        },

        4728: {
            "name": "User Added to Administrator Group",
            "severity": "Critical",
            "icon": "🚨",
            "category": "Privilege",
            "description": "A user was added to the Administrators group.",
            "mitre_id": "T1098",
            "mitre_tactic": "Persistence — Account Manipulation"
        },

        4799: {
            "name": "Local Group Membership Enumerated",
            "severity": "Medium",
            "icon": "🟠",
            "category": "Enumeration",
            "description": "A process queried local group membership.",
            "mitre_id": "T1069",
            "mitre_tactic": "Discovery — Permission Groups Discovery"
        },

        5379: {
            "name": "Credential Manager Access",
            "severity": "Medium",
            "icon": "🟠",
            "category": "Credential Access",
            "description": "Stored credentials were accessed.",
            "mitre_id": "T1555",
            "mitre_tactic": "Credential Access — Credentials from Password Stores"
        },

        1102: {
            "name": "Security Log Cleared",
            "severity": "Critical",
            "icon": "🚨",
            "category": "Log Management",
            "description": "The Windows Security log was cleared.",
            "mitre_id": "T1070.001",
            "mitre_tactic": "Defense Evasion — Indicator Removal: Clear Windows Event Logs"
        }
    }

    return threats.get(
        event_id,
        {
            "name": "Unknown Event",
            "severity": "Info",
            "icon": "⚪",
            "category": "Unknown",
            "description": "This event is not yet classified.",
            "mitre_id": None,
            "mitre_tactic": None
        }
    )