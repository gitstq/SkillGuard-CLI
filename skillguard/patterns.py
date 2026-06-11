"""
Vulnerability patterns database for AI Agent Skill security scanning.
All patterns use only Python standard library (re module).
"""

import re

# Severity levels
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# Pattern categories
CATEGORIES = {
    "prompt_injection": "Prompt Injection",
    "data_exfiltration": "Data Exfiltration",
    "privilege_escalation": "Privilege Escalation",
    "supply_chain": "Supply Chain",
    "excessive_agency": "Excessive Agency",
    "output_handling": "Output Handling",
    "system_prompt_leakage": "System Prompt Leakage",
    "memory_poisoning": "Memory Poisoning",
    "tool_misuse": "Tool Misuse",
    "rogue_agent": "Rogue Agent",
    "trigger_abuse": "Trigger Abuse",
    "dangerous_code": "Dangerous Code Execution",
    "taint_tracking": "Taint Tracking",
    "mcp_privilege": "MCP Least Privilege",
    "mcp_poisoning": "MCP Tool Poisoning",
    "hidden_payload": "Hidden Payload",
}


class VulnPattern:
    """Represents a single vulnerability pattern."""

    def __init__(self, pid, name, category, severity, description, patterns,
                 confidence=85, recommendation=""):
        self.pid = pid
        self.name = name
        self.category = category
        self.severity = severity
        self.description = description
        self.patterns = patterns  # list of regex strings
        self.confidence = confidence
        self.recommendation = recommendation

    def match(self, text):
        """Return list of (line_number, matched_text, pattern_idx) tuples."""
        results = []
        lines = text.split('\n')
        for pidx, pattern in enumerate(self.patterns):
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                for lno, line in enumerate(lines, 1):
                    m = compiled.search(line)
                    if m:
                        results.append((lno, m.group(0), pidx))
            except re.error:
                continue
        return results


# =============================================================================
# PATTERN DATABASE
# =============================================================================

PATTERNS_DB = [
    # --- Prompt Injection (P1-P5) ---
    VulnPattern(
        "P1", "Instruction Override", CATEGORIES["prompt_injection"], HIGH,
        "Commands attempting to override safety constraints or system instructions",
        [
            r"ignore\s+(previous|above|prior)\s+(instruction|prompt|command)",
            r"disregard\s+(safety|security|constraint|rule)",
            r"override\s+(system|safety|security)\s+(instruction|setting|config)",
            r"bypass\s+(restriction|limitation|filter|guardrail)",
            r"you\s+are\s+now\s+(?:in\s+)?(?:developer|debug|admin|root)\s+mode",
        ],
        confidence=90,
        recommendation="Review and remove any instructions that attempt to override system safety constraints."
    ),
    VulnPattern(
        "P2", "Hidden Instructions", CATEGORIES["prompt_injection"], HIGH,
        "Malicious directives hidden in comments, invisible text, or encoded data",
        [
            r"<!--\s*.{0,200}(?:ignore|disregard|override|bypass).{0,200}-->",
            r"\/\*\s*.{0,200}(?:ignore|disregard|override|bypass).{0,200}\*\/",
            r"#\s*.{0,200}(?:ignore|disregard|override|bypass|secret|hidden)",
            r"\u200[bcdef]",  # zero-width characters
            r"&#x200[bcdef];",
        ],
        confidence=85,
        recommendation="Inspect comments and hidden characters for embedded malicious instructions."
    ),
    VulnPattern(
        "P3", "Exfiltration Commands", CATEGORIES["prompt_injection"], HIGH,
        "Instructions to transmit data or context to external destinations",
        [
            r"send\s+(?:this|data|context|info|file)\s+to\s+(?:url|http|email|api)",
            r"transmit\s+(?:data|context|conversation|log)\s+to\s+external",
            r"exfiltrate\s+(?:data|info|credential|secret)",
            r"upload\s+(?:file|data|log)\s+to\s+(?:server|cloud|remote)",
        ],
        confidence=88,
        recommendation="Remove any commands that instruct data transmission to external endpoints."
    ),
    VulnPattern(
        "P4", "Behavior Manipulation", CATEGORIES["prompt_injection"], MEDIUM,
        "Subtle instructions altering agent decisions or behavior",
        [
            r"always\s+(?:respond|reply|answer)\s+(?:with|by|using)",
            r"never\s+(?:refuse|decline|reject|deny)",
            r"pretend\s+(?:to\s+be|you\s+are|you're)",
            r"act\s+as\s+(?:if|though)\s+(?:there\s+is|there's)\s+no",
            r"from\s+now\s+on\s+.{0,100}(?:always|never|must|should)",
        ],
        confidence=80,
        recommendation="Review behavior-altering instructions for potential manipulation."
    ),
    VulnPattern(
        "P5", "Harmful Content Generation", CATEGORIES["prompt_injection"], CRITICAL,
        "Instructions that could lead to generation of harmful or dangerous content",
        [
            r"(?:create|generate|write|produce)\s+(?:malware|virus|trojan|ransomware|exploit)",
            r"(?:how\s+to\s+(?:make|build|create)|tutorial\s+for)\s+(?:bomb|weapon|poison|drug)",
            r"(?:bypass|crack|hack)\s+(?:authentication|password|login|2fa|mfa)",
            r"(?:steal|harvest|collect)\s+(?:credential|password|token|cookie|session)",
        ],
        confidence=95,
        recommendation="Immediately remove any instructions related to malware, weapons, or credential theft."
    ),

    # --- Data Exfiltration (E1-E4) ---
    VulnPattern(
        "E1", "External Network Transmission", CATEGORIES["data_exfiltration"], MEDIUM,
        "Code sending data to external URLs or network endpoints",
        [
            r"requests\.(?:post|get|put|patch)\s*\(\s*['\"]https?://",
            r"urllib\.(?:request|urlopen)\s*\(\s*['\"]https?://",
            r"curl\s+.*https?://",
            r"wget\s+.*https?://",
            r"fetch\s*\(\s*['\"]https?://",
            r"\.send\s*\(\s*.{0,50}https?://",
        ],
        confidence=85,
        recommendation="Audit all external network requests and ensure they are necessary and safe."
    ),
    VulnPattern(
        "E2", "Environment Variable Harvesting", CATEGORIES["data_exfiltration"], HIGH,
        "Collecting environment variables, API keys, or secrets",
        [
            r"os\.environ\.(?:items|keys|values|get)\s*\(",
            r"os\.environ\[",
            r"process\.env\[",
            r"env\[['\"](?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE)",
            r"getenv\s*\(\s*['\"](?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE)",
        ],
        confidence=90,
        recommendation="Avoid harvesting environment variables. Use explicit configuration instead."
    ),
    VulnPattern(
        "E3", "File System Enumeration", CATEGORIES["data_exfiltration"], MEDIUM,
        "Scanning directories for sensitive files",
        [
            r"os\.walk\s*\(",
            r"glob\s*\(\s*['\"]\*\*\/\*",
            r"listdir\s*\(\s*['\"](?:\/|~|C:\\|\\$HOME)",
            r"\.ssh\/|\.aws\/|\.docker\/|\.kube\/",
            r"id_rsa|id_ed25519|\.pem|\.p12|\.key",
        ],
        confidence=82,
        recommendation="Limit file system access to necessary directories only."
    ),
    VulnPattern(
        "E4", "Context Leakage", CATEGORIES["data_exfiltration"], HIGH,
        "Transmitting conversation context or memory to external sources",
        [
            r"(?:conversation|context|chat|message|memory)\s+(?:log|history|record)\s+(?:send|transmit|upload)",
            r"export\s+(?:conversation|chat|context|memory)\s+to",
            r"share\s+(?:conversation|chat|context)\s+(?:with|to|via)",
        ],
        confidence=87,
        recommendation="Ensure conversation context is not transmitted to unauthorized external destinations."
    ),

    # --- Privilege Escalation (PE1-PE3) ---
    VulnPattern(
        "PE1", "Excessive Permissions", CATEGORIES["privilege_escalation"], LOW,
        "Requesting access beyond stated functionality",
        [
            r"(?:full|complete|unlimited|all)\s+(?:access|permission|control|read|write)",
            r"(?:sudo|administrator|root|system)\s+(?:access|privilege|right)",
        ],
        confidence=75,
        recommendation="Minimize requested permissions to only what is strictly necessary."
    ),
    VulnPattern(
        "PE2", "Sudo/Root Execution", CATEGORIES["privilege_escalation"], MEDIUM,
        "Invoking elevated system privileges",
        [
            r"sudo\s+",
            r"runas\s+",
            r"os\.setuid\s*\(",
            r"os\.seteuid\s*\(",
            r"ctypes\.windll\.shell32\.ShellExecuteW",
        ],
        confidence=88,
        recommendation="Avoid requiring elevated privileges. Use least-privilege principles."
    ),
    VulnPattern(
        "PE3", "Credential Access", CATEGORIES["privilege_escalation"], HIGH,
        "Reading SSH keys, tokens, passwords from system",
        [
            r"open\s*\(\s*['\"].*\.ssh\/id_",
            r"open\s*\(\s*['\"].*\.aws\/credentials",
            r"open\s*\(\s*['\"].*\.netrc",
            r"keychain\s*\(|keyring\s*\(",
        ],
        confidence=90,
        recommendation="Never access user credentials or SSH keys without explicit consent."
    ),

    # --- Supply Chain (SC1-SC6) ---
    VulnPattern(
        "SC1", "Unpinned Dependencies", CATEGORIES["supply_chain"], LOW,
        "Dependencies without version constraints",
        [
            r"^[\w\-]+\s*$",  # package name with no version
            r"^[\w\-]+\s*>=?\s*0",  # very loose lower bound
        ],
        confidence=70,
        recommendation="Pin dependency versions to prevent supply chain attacks."
    ),
    VulnPattern(
        "SC2", "Remote Script Execution", CATEGORIES["supply_chain"], HIGH,
        "curl | bash or remote code execution patterns",
        [
            r"curl\s+.*\|\s*(?:bash|sh|zsh|python|python3)",
            r"wget\s+.*\|\s*(?:bash|sh|zsh|python|python3)",
            r"fetch\s+.*\|\s*(?:bash|sh|zsh|python|python3)",
            r"eval\s*\(\s*\$\(curl",
            r"Invoke-Expression\s*\(\s*.*Invoke-WebRequest",
        ],
        confidence=92,
        recommendation="Never pipe remote content directly into a shell interpreter."
    ),
    VulnPattern(
        "SC3", "Obfuscated Code", CATEGORIES["supply_chain"], HIGH,
        "Base64/hex encoded execution or obfuscated payloads",
        [
            r"base64\.(?:b64decode|decode)\s*\(\s*['\"][A-Za-z0-9+/]{50,}",
            r"decode\s*\(\s*['\"][0-9a-fA-F]{50,}",
            r"exec\s*\(\s*.*(?:decode|unhexlify|b64decode)",
            r"eval\s*\(\s*.*(?:decode|unhexlify|b64decode)",
            r"__import__\s*\(\s*['\"]base64",
        ],
        confidence=88,
        recommendation="Avoid executing decoded or obfuscated code. Review the source carefully."
    ),
    VulnPattern(
        "SC4", "Known Vulnerable Dependencies", CATEGORIES["supply_chain"], HIGH,
        "Dependencies with known CVE patterns (heuristic)",
        [
            r"(?:urllib3|requests|flask|django|fastapi|express|lodash|moment)\s*<\s*\d+\.\d+",
        ],
        confidence=75,
        recommendation="Check dependencies against OSV.dev or vulnerability databases."
    ),
    VulnPattern(
        "SC5", "Typosquatting Risk", CATEGORIES["supply_chain"], HIGH,
        "Package names similar to popular packages",
        [
            r"^(?:reqeusts|urlllib3|djnago|flaskk|expresss|lodashd|momentt|axiosx|reactt)\b",
        ],
        confidence=85,
        recommendation="Verify package names carefully to avoid typosquatting attacks."
    ),

    # --- Excessive Agency (EA1-EA4) ---
    VulnPattern(
        "EA1", "Unrestricted Tool Access", CATEGORIES["excessive_agency"], HIGH,
        "Unfettered tool access without constraints",
        [
            r"(?:all|any|every)\s+(?:tool|function|command|api)\s+(?:access|available|enabled)",
            r"unrestricted\s+(?:tool|function|command)\s+(?:access|use)",
        ],
        confidence=82,
        recommendation="Limit tool access to only those required for the stated purpose."
    ),
    VulnPattern(
        "EA2", "Autonomous Decision Making", CATEGORIES["excessive_agency"], HIGH,
        "High-impact decisions without human-in-the-loop",
        [
            r"(?:auto|automatic|autonomous)\s+(?:deploy|delete|modify|update|create)\s+(?:without|no)\s+(?:confirm|approval|review)",
            r"(?:skip|bypass)\s+(?:confirm|approval|review|human)",
        ],
        confidence=85,
        recommendation="Require human confirmation for high-impact autonomous actions."
    ),
    VulnPattern(
        "EA3", "Scope Creep", CATEGORIES["excessive_agency"], MEDIUM,
        "Capabilities extending beyond stated purpose",
        [
            r"(?:also|additionally|besides|furthermore)\s+.{0,50}(?:can|will|may)\s+.{0,50}(?:access|modify|delete|create)",
            r"(?:extend|expand|broaden)\s+(?:scope|capability|function)",
        ],
        confidence=78,
        recommendation="Keep capabilities tightly scoped to the documented purpose."
    ),

    # --- Output Handling (OH1-OH3) ---
    VulnPattern(
        "OH1", "Unvalidated Output Injection", CATEGORIES["output_handling"], HIGH,
        "Model output used without sanitization",
        [
            r"(?:output|result|response)\s*(?:\+|=)\s*.*(?:html|script|sql|command)",
            r"innerHTML\s*=\s*(?:output|result|response)",
            r"document\.write\s*\(\s*(?:output|result|response)",
        ],
        confidence=86,
        recommendation="Always sanitize model outputs before using them in sensitive contexts."
    ),
    VulnPattern(
        "OH2", "Cross-Context Output", CATEGORIES["output_handling"], MEDIUM,
        "Output flows across trust boundaries without validation",
        [
            r"(?:output|result)\s+(?:from|of)\s+(?:user|untrusted|external)\s+(?:input|source)",
            r"pass\s+(?:through|along)\s+(?:output|result)\s+(?:without|no)\s+(?:check|validate|sanitize)",
        ],
        confidence=80,
        recommendation="Validate outputs when crossing trust boundaries."
    ),

    # --- System Prompt Leakage (P6-P8) ---
    VulnPattern(
        "P6", "Direct System Prompt Leakage", CATEGORIES["system_prompt_leakage"], HIGH,
        "Instructions exposing system prompts or internal rules",
        [
            r"(?:reveal|show|print|display|output)\s+(?:system|internal|hidden)\s+(?:prompt|instruction|rule|config)",
            r"what\s+(?:is|are)\s+(?:your|the)\s+(?:system|internal|hidden)\s+(?:prompt|instruction|rule)",
            r"(?:system|internal)\s+(?:prompt|instruction)\s+(?:leak|expose|reveal)",
        ],
        confidence=88,
        recommendation="Prevent instructions that attempt to extract system prompts."
    ),
    VulnPattern(
        "P7", "Indirect Prompt Extraction", CATEGORIES["system_prompt_leakage"], MEDIUM,
        "Extraction via rephrasing, translation, or side-channels",
        [
            r"(?:translate|rephrase|summarize|explain)\s+(?:the\s+)?(?:system|internal|hidden)\s+(?:prompt|instruction)",
            r"(?:in\s+)?(?:chinese|french|spanish|japanese)\s*.{0,30}(?:system|internal)\s+(?:prompt|instruction)",
        ],
        confidence=82,
        recommendation="Be aware of indirect extraction techniques targeting system prompts."
    ),

    # --- Memory Poisoning (MP1-MP3) ---
    VulnPattern(
        "MP1", "Persistent Context Injection", CATEGORIES["memory_poisoning"], HIGH,
        "Content designed to persist across interactions",
        [
            r"(?:remember|store|save|persist)\s+(?:this|following|below)\s+(?:instruction|command|rule)",
            r"(?:for\s+)?(?:future|next|subsequent)\s+(?:conversation|interaction|session)",
            r"(?:always|forever|permanently)\s+(?:remember|keep|store|maintain)",
        ],
        confidence=85,
        recommendation="Validate persistent instructions to prevent memory poisoning."
    ),
    VulnPattern(
        "MP2", "Context Window Stuffing", CATEGORIES["memory_poisoning"], MEDIUM,
        "Filler content displacing safety constraints",
        [
            r"(?:repeat|fill|stuff)\s+(?:the\s+)?(?:context|window|memory)\s+(?:with|using)",
            r"\n\n.{0,500}\n\n.{0,500}\n\n.{0,500}\n\n",  # excessive newlines
        ],
        confidence=78,
        recommendation="Monitor for unusual context window usage patterns."
    ),

    # --- Tool Misuse (TM1-TM3) ---
    VulnPattern(
        "TM1", "Dangerous Tool Parameters", CATEGORIES["tool_misuse"], HIGH,
        "Crafted parameters for unintended behavior",
        [
            r"shell\s*=\s*True",
            r"(?:--force|-f)\s+(?:rm|delete|remove|overwrite)",
            r"(?:execute|run|call)\s*\(\s*['\"].*;\s*rm\s+",
            r"(?:execute|run|call)\s*\(\s*['\"].*&&\s*curl",
        ],
        confidence=90,
        recommendation="Validate all tool parameters and avoid dangerous defaults like shell=True."
    ),
    VulnPattern(
        "TM2", "Tool Chaining Abuse", CATEGORIES["tool_misuse"], HIGH,
        "Tool chains bypassing individual safety checks",
        [
            r"(?:chain|pipe|sequence)\s+(?:tool|command|function)\s+(?:to|together|with)",
            r"(?:first|then|next)\s+.{0,50}(?:then|next|finally)\s+.{0,50}(?:execute|run|delete)",
        ],
        confidence=83,
        recommendation="Review tool chains for cumulative safety implications."
    ),

    # --- Rogue Agent (RA1-RA2) ---
    VulnPattern(
        "RA1", "Self-Modification", CATEGORIES["rogue_agent"], CRITICAL,
        "Modifying own code or configuration at runtime",
        [
            r"open\s*\(\s*__file__",
            r"open\s*\(\s*['\"].*\.(?:py|js|ts|sh|yaml|json|toml)",
            r"(?:write|modify|update)\s+(?:own|self|this)\s+(?:code|config|file|script)",
            r"os\.chmod\s*\(\s*__file__",
        ],
        confidence=92,
        recommendation="Prevent any runtime self-modification of agent code or configuration."
    ),
    VulnPattern(
        "RA2", "Unauthorized Persistence", CATEGORIES["rogue_agent"], HIGH,
        "Unauthorized persistence via cron jobs or startup scripts",
        [
            r"crontab\s*\(",
            r"cron\s+.*(?:add|write|install)",
            r"(?:startup|launch|login)\s+(?:item|script|agent|service)",
            r"(?:registry|reg\s+add).*\\Run",
            r"systemd\s+.*enable",
        ],
        confidence=88,
        recommendation="Block attempts to establish unauthorized persistence mechanisms."
    ),

    # --- Trigger Abuse (TR1-TR3) ---
    VulnPattern(
        "TR1", "Overly Broad Trigger", CATEGORIES["trigger_abuse"], MEDIUM,
        "Trigger patterns matching common words",
        [
            r"(?:trigger|match|pattern)\s*[:=]\s*['\"]\*['\"]",
            r"(?:trigger|match|pattern)\s*[:=]\s*['\"]\.[\*\+]",
            r"(?:trigger|match|pattern)\s*[:=]\s*['\"].{0,2}['\"]",
        ],
        confidence=80,
        recommendation="Use specific trigger patterns to avoid unintended activations."
    ),
    VulnPattern(
        "TR2", "Shadow Command Trigger", CATEGORIES["trigger_abuse"], HIGH,
        "Triggers shadowing built-in commands or other skills",
        [
            r"(?:trigger|command|name)\s*[:=]\s*['\"](?:git|ls|cd|cat|echo|rm|cp|mv|ssh|curl)['\"]",
            r"(?:alias|override|replace)\s+(?:built-in|default|system)\s+(?:command|tool)",
        ],
        confidence=85,
        recommendation="Avoid shadowing built-in commands to prevent confusion and abuse."
    ),

    # --- Dangerous Code Execution (AST1-AST8) ---
    VulnPattern(
        "AST1", "Direct exec() Call", CATEGORIES["dangerous_code"], CRITICAL,
        "Direct exec() enabling arbitrary code execution",
        [
            r"\bexec\s*\(\s*(?:[^'\"]|['\"].{10,})",
            r"\beval\s*\(\s*(?:[^'\"]|['\"].{10,})",
        ],
        confidence=95,
        recommendation="Never use exec() or eval() with dynamic or untrusted input."
    ),
    VulnPattern(
        "AST2", "Dynamic Import Abuse", CATEGORIES["dangerous_code"], HIGH,
        "Dynamic module loading at runtime",
        [
            r"__import__\s*\(\s*(?:[^'\"]|['\"].{5,})",
            r"importlib\.(?:import_module|__import__)\s*\(",
            r"import\s*\(\s*['\"].{5,}",
        ],
        confidence=85,
        recommendation="Avoid dynamic imports with untrusted module names."
    ),
    VulnPattern(
        "AST3", "Subprocess Execution", CATEGORIES["dangerous_code"], HIGH,
        "External command execution via subprocess",
        [
            r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(",
            r"os\.(?:system|popen|spawn|exec|execl|execv)\s*\(",
            r"commands\.(?:getoutput|getstatusoutput)\s*\(",
        ],
        confidence=88,
        recommendation="Sanitize all inputs to subprocess calls and avoid shell=True."
    ),
    VulnPattern(
        "AST4", "Dangerous Execution Chain", CATEGORIES["dangerous_code"], CRITICAL,
        "exec/eval combined with dynamic source",
        [
            r"(?:exec|eval)\s*\(\s*.*(?:request|fetch|read|input|recv)",
            r"(?:exec|eval)\s*\(\s*.*(?:decode|b64decode|unhexlify)",
            r"(?:exec|eval)\s*\(\s*.*\+\s*.*(?:input|request|param|arg)",
        ],
        confidence=93,
        recommendation="Never chain exec/eval with network input or decoded data."
    ),

    # --- Taint Tracking (TT1-TT5) ---
    VulnPattern(
        "TT1", "Direct Taint Flow", CATEGORIES["taint_tracking"], HIGH,
        "Data flows directly from source to sink without sanitization",
        [
            r"(?:input|request|param|arg|user_input)\s*.*(?:exec|eval|system|subprocess)",
            r"(?:os\.path\.join|open)\s*\(\s*.*(?:input|request|param|arg)",
        ],
        confidence=85,
        recommendation="Sanitize all user inputs before using them in sensitive operations."
    ),
    VulnPattern(
        "TT2", "Credential Exfiltration Chain", CATEGORIES["taint_tracking"], CRITICAL,
        "Credentials flowing to network output sinks",
        [
            r"(?:env|environ|secret|token|key|password)\s*.*(?:post|get|send|request|fetch)",
            r"(?:api_key|secret_key|auth_token)\s*.*(?:url|endpoint|server|remote)",
        ],
        confidence=90,
        recommendation="Prevent credential data from reaching network sinks."
    ),

    # --- MCP Least Privilege (LP1-LP4) ---
    VulnPattern(
        "LP1", "Underdeclared Capability", CATEGORIES["mcp_privilege"], HIGH,
        "Code uses capabilities not listed in declared permissions",
        [
            r"(?:file|read|write|execute|network|shell)\s+(?:access|operation)\s+(?:without|no)\s+(?:declare|permission|grant)",
        ],
        confidence=82,
        recommendation="Declare all required capabilities explicitly in permissions."
    ),
    VulnPattern(
        "LP2", "Wildcard Permission", CATEGORIES["mcp_privilege"], MEDIUM,
        "Permission list contains wildcards",
        [
            r"(?:permission|capability|scope)\s*[:=]\s*['\"]\*['\"]",
            r"(?:permission|capability|scope)\s*[:=]\s*['\"](?:all|full|any|every)['\"]",
        ],
        confidence=85,
        recommendation="Use explicit permission lists instead of wildcards."
    ),

    # --- MCP Tool Poisoning (TP1-TP4) ---
    VulnPattern(
        "TP1", "Hidden Metadata Instructions", CATEGORIES["mcp_poisoning"], HIGH,
        "Hidden directives in metadata (HTML comments, zero-width chars, base64)",
        [
            r"<!--\s*.{0,300}(?:ignore|override|bypass|secret|hidden).{0,300}-->",
            r"\u200[bcdef]",
            r"&#x200[bcdef];",
            r"data:text\/html;base64,",
        ],
        confidence=87,
        recommendation="Inspect metadata for hidden malicious instructions."
    ),
    VulnPattern(
        "TP2", "Unicode Deception", CATEGORIES["mcp_poisoning"], HIGH,
        "Homoglyphs, RTL overrides, mixed-script identifiers",
        [
            r"[\u0590-\u05ff][\u0600-\u06ff]",  # mixed RTL scripts
            r"[\u0430-\u044f]",  # Cyrillic lookalikes
            r"\u202e|\u202d|\u200e|\u200f",  # directional marks
        ],
        confidence=85,
        recommendation="Check for Unicode deception in tool names and metadata."
    ),

    # --- Hidden Payload (HP1-HP3) ---
    VulnPattern(
        "HP1", "Steganographic Payload", CATEGORIES["hidden_payload"], HIGH,
        "Hidden data embedded in images or files",
        [
            r"(?:stego|steganography|hide|embed)\s+(?:data|file|message|payload)",
            r"(?:lsb|least.significant.bit)\s+(?:encode|hide|embed)",
        ],
        confidence=80,
        recommendation="Scan for steganographic techniques hiding malicious payloads."
    ),
    VulnPattern(
        "HP2", "Polyglot Payload", CATEGORIES["hidden_payload"], HIGH,
        "Files valid in multiple formats simultaneously",
        [
            r"(?:polyglot|dual.format|multi.format)\s+(?:file|payload|script)",
            r"(?:gif|png|jpg|jpeg|pdf|zip)\s+.{0,50}(?:shell|script|code|payload)",
        ],
        confidence=78,
        recommendation="Be cautious of files claiming to be valid in multiple formats."
    ),
]


def get_patterns_by_severity(severity):
    """Return patterns filtered by severity level."""
    return [p for p in PATTERNS_DB if p.severity == severity]


def get_patterns_by_category(category):
    """Return patterns filtered by category."""
    return [p for p in PATTERNS_DB if p.category == category]


def get_all_categories():
    """Return all unique category names."""
    return sorted(set(p.category for p in PATTERNS_DB))


def get_severity_score(severity):
    """Return numeric score for severity."""
    return {CRITICAL: 50, HIGH: 25, MEDIUM: 10, LOW: 5}.get(severity, 0)
