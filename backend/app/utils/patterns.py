"""
Compiled regex patterns for deterministic sensitive data and security threat detection.
Covers: XSS, SQLi, SSRF, LFI/Path Traversal, Command Injection, Log4Shell, XXE, RCE,
WAF bypass, F5 ASM structured logs, network packet anomalies, IDOR, open redirect, LDAP injection.
"""

import re
import urllib.parse

# ── Sensitive Data Patterns ──────────────────────────────────────────────────

EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(
    r"(?:\+?\d{1,3}[-.\\s]?)?\(?\d{2,4}\)?[-.\\s]?\d{3,4}[-.\\s]?\d{4}",
)

API_KEY_PATTERN = re.compile(
    r"(?:"
    r"(?:api[_\-]?key|apikey|api_secret|access[_\-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{8,}['\"]?"
    r"|AKIA[0-9A-Z]{16}"
    r"|sk-[a-zA-Z0-9\-]{8,}"
    r"|key-[a-zA-Z0-9\-]{8,}"
    r")",
    re.IGNORECASE,
)

PASSWORD_PATTERN = re.compile(
    r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?[^\s'\"]{4,}['\"]?",
    re.IGNORECASE,
)

TOKEN_PATTERN = re.compile(
    r"(?:"
    r"(?:token|auth_token|access_token|bearer|jwt)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_.]{8,}['\"]?"
    r"|Bearer\s+[a-zA-Z0-9\-_.]+(?:\.[a-zA-Z0-9\-_.]+){1,}"
    r")",
    re.IGNORECASE,
)

SECRET_PATTERN = re.compile(
    r"(?:secret|client_secret|app_secret|private_key)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_/+=]{8,}['\"]?",
    re.IGNORECASE,
)

# ── XSS Patterns ─────────────────────────────────────────────────────────────

XSS_PATTERN = re.compile(
    r"(?:"
    r"<script[\s>]"
    r"|</script>"
    r"|javascript\s*:"
    r"|on(?:load|error|click|mouseover|focus|blur|change|submit|keyup|keydown)\s*="
    r"|alert\s*\("
    r"|document\.cookie"
    r"|document\.domain"
    r"|eval\s*\("
    r"|String\.fromCharCode"
    r'|<img[^>]+src\s*=\s*["\']?\s*(?:javascript|data):'
    r"|<svg[^>]+on\w+\s*="
    r"|<iframe[^>]+src"
    r")",
    re.IGNORECASE,
)

XSS_ENCODED_PATTERN = re.compile(
    r"(?:"
    r"%3[Cc]script"          # <script URL-encoded
    r"|%3[Ee]"               # > URL-encoded
    r"|%22%3[Ee]%3[Cc]"      # "><script URL-encoded
    r"|&#[xX]?0*3[Cc]"       # HTML entity <
    r"|\\u003[Cc]"           # Unicode escape <
    r"|%3[Cc]img"
    r"|%6[Aa]avascript"
    r")",
    re.IGNORECASE,
)

# ── SQL Injection Patterns ────────────────────────────────────────────────────

SQL_INJECTION_PATTERN = re.compile(
    r"(?:'\s*(?:OR|AND)\s+['\\d]|--\s*$|;\s*DROP\s+TABLE"
    r"|UNION\s+(?:ALL\s+)?SELECT|/\*.*\*/"
    r"|(?:exec|execute)\s*\(|xp_cmdshell"
    r"|SLEEP\s*\(\d+\)|BENCHMARK\s*\("
    r"|(?:1=1|1='1'|'a'='a')"
    r"|OR\s+1\s*=\s*1"
    r"|WAITFOR\s+DELAY"
    r")",
    re.IGNORECASE,
)

# ── Path Traversal / LFI ──────────────────────────────────────────────────────

PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:"
    r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f"
    r"|%2e%2e%5c|%252e%252e"
    r"|/etc/passwd|/etc/shadow|/proc/self"
    r"|/windows/system32|/win\.ini|/boot\.ini"
    r"|\.\.%5[Cc]"
    r")",
    re.IGNORECASE,
)

# ── Command Injection ─────────────────────────────────────────────────────────

COMMAND_INJECTION_PATTERN = re.compile(
    r"(?:"
    r";\s*(?:rm|wget|curl|bash|sh|nc|ncat|netcat|python|perl|ruby)\s"
    r"|\|\s*(?:nc|bash|sh|cmd)\s"
    r"|`[^`]+`"
    r"|\$\([^)]+\)"
    r"|&&\s*(?:rm|cat|wget|curl|bash)"
    r"|\|\|\s*(?:rm|cat|wget|curl|bash)"
    r"|;cat\s+/etc/"
    r")",
    re.IGNORECASE,
)

# ── SSRF Patterns ─────────────────────────────────────────────────────────────

SSRF_PATTERN = re.compile(
    r"(?:"
    r"169\.254\.169\.254"                   # AWS metadata endpoint
    r"|metadata\.google\.internal"
    r"|169\.254\.170\.2"                    # ECS metadata
    r"|(?:url|redirect|callback|next|dest(?:ination)?|return)\s*=.*?"
    r"(?:https?://(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.))"
    r"|file:///"
    r"|dict://|gopher://|ftp://"
    r")",
    re.IGNORECASE,
)

# ── Log4Shell (CVE-2021-44228) ────────────────────────────────────────────────

LOG4SHELL_PATTERN = re.compile(
    r"(?:"
    r"\$\{jndi:"
    r"|\$\{(?:\$\{[^}]+\}|[^}])*jndi"   # obfuscated variants
    r"|\$\{lower:j\}"
    r"|\$\{::-j\}"
    r"|\$\{upper:j\}"
    r"|%24%7Bjndi"                        # URL-encoded ${jndi
    r"|\$\{env:"
    r"|\$\{sys:"
    r")",
    re.IGNORECASE,
)

# ── XXE Patterns ─────────────────────────────────────────────────────────────

XXE_PATTERN = re.compile(
    r"(?:"
    r"<!ENTITY\s+\w+\s+SYSTEM"
    r"|<!DOCTYPE[^>]+\[<!ENTITY"
    r"|SYSTEM\s+['\"]file://"
    r"|SYSTEM\s+['\"]http://"
    r"|<!ELEMENT[^>]+ANY>"
    r")",
    re.IGNORECASE,
)

# ── RCE Patterns ─────────────────────────────────────────────────────────────

RCE_PATTERN = re.compile(
    r"(?:"
    r"eval\s*\([^)]*(?:base64_decode|gzinflate|str_rot13)"
    r"|system\s*\(['\"]"
    r"|shell_exec\s*\("
    r"|passthru\s*\("
    r"|popen\s*\("
    r"|proc_open\s*\("
    r"|__import__\s*\(['\"]os['\"]"
    r"|subprocess\.(?:call|Popen|run)\s*\("
    r"|Runtime\.getRuntime\(\)\.exec"
    r")",
    re.IGNORECASE,
)

# ── WAF Bypass Detection ──────────────────────────────────────────────────────

WAF_BYPASS_PATTERN = re.compile(
    r"(?:"
    r"request_status\s*=\s*['\"]?passed['\"]?"  # WAF passed a dangerous request
    r"|violation_rating\s*=\s*['\"]?[4-5]['\"]?"  # High violation rating
    r"|staged_sig_names\s*=\s*['\"]?(?!N/A)[^'\"]*['\"]?"  # Staged (unblocked) signatures matched
    r")",
    re.IGNORECASE,
)

# ── F5 BIG-IP ASM / Syslog Structured Log ────────────────────────────────────

F5_ASM_PATTERN = re.compile(
    r"(?:ASM:|unit_hostname=|management_ip_address=|http_class_name=|policy_name=|violation_rating=)",
    re.IGNORECASE,
)

# ── Open Redirect ─────────────────────────────────────────────────────────────

OPEN_REDIRECT_PATTERN = re.compile(
    r"(?:redirect|next|return|goto|url|dest(?:ination)?)\s*=\s*(?:https?://|//)[^&\s\"']*",
    re.IGNORECASE,
)

# ── LDAP Injection ────────────────────────────────────────────────────────────

LDAP_INJECTION_PATTERN = re.compile(
    r"(?:\)\(cn=\*\)|\*\)\(uid=\*|\)\(\|\(|\*\)\(objectClass=\*)",
    re.IGNORECASE,
)

# ── IDOR Patterns ─────────────────────────────────────────────────────────────

IDOR_PATTERN = re.compile(
    r"(?:/(?:api|v\d+)/(?:user|account|order|profile|admin)/\d+)",
    re.IGNORECASE,
)

# ── Network Packet Anomaly Patterns ──────────────────────────────────────────

SYN_FLOOD_PATTERN = re.compile(
    r"(?:SYN\s+SYN\s+SYN|Flags\s*=\s*S{3,}|syn_flood|SYN\s+Flood|\bSYN\b.{0,30}\bSYN\b.{0,30}\bSYN\b)",
    re.IGNORECASE,
)

PORT_SCAN_PATTERN = re.compile(
    r"(?:"
    r"port\s+scan|Nmap\s+scan|nmap\s+-sS|masscan"
    r"|(?:Dest|DST|destination)\s+port[:\s]+(?:\d+\s*,\s*){4,}"   # many different ports
    r"|RST\s+RST\s+RST"
    r")",
    re.IGNORECASE,
)

ARP_SPOOF_PATTERN = re.compile(
    r"(?:ARP\s+spoof|duplicate\s+(?:IP|ARP)|arp\s+poison|gratuitous\s+ARP\s+with\s+different)",
    re.IGNORECASE,
)

DNS_EXFIL_PATTERN = re.compile(
    r"(?:"
    r"TXT\s+record.{0,50}(?:[A-Za-z0-9+/]{20,}=*)"   # base64 in DNS TXT
    r"|DNS\s+tunnel"
    r"|dnscat"
    r"|iodine"
    r")",
    re.IGNORECASE,
)

# ── Security Issue Patterns ──────────────────────────────────────────────────

STACK_TRACE_PATTERN = re.compile(
    r"(?:Traceback \(most recent call last\)|at\s+\S+:\d+|at\s+\S+\.\S+\(.*:\d+\)|Exception in thread|"
    r"^\s+File\s+\".*\",\s+line\s+\d+|java\.\w+\..*Exception|"
    r"panic:|runtime error:)",
    re.MULTILINE,
)

DEBUG_MODE_PATTERN = re.compile(
    r"(?:DEBUG\s*[:=]\s*(?:true|1|on|yes|enabled)|debug\s+mode\s+(?:is\s+)?(?:on|enabled|active)|DEBUG\s+stack\s+trace)",
    re.IGNORECASE,
)

HARDCODED_CREDENTIAL_PATTERN = re.compile(
    r"(?:root:.*@|admin:.*@|mysql://\w+:\w+@|postgres://\w+:\w+@|mongodb://\w+:\w+@|"
    r"redis://:\w+@|ftp://\w+:\w+@)",
    re.IGNORECASE,
)

# ── Log Analysis Patterns ────────────────────────────────────────────────────

FAILED_LOGIN_PATTERN = re.compile(
    r"(?:failed\s+(?:login|auth(?:entication)?|sign[\s-]?in)|"
    r"invalid\s+(?:credentials?|password|username)|"
    r"(?:login|auth)\s+(?:fail(?:ure|ed)?|denied|rejected)|"
    r"access\s+denied|unauthorized\s+access|"
    r"401\s+unauthorized)",
    re.IGNORECASE,
)

IP_ADDRESS_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)

SUSPICIOUS_IP_INDICATORS = re.compile(
    r"(?:blocked|banned|blacklisted|malicious|suspicious)\s+(?:ip|address|host)",
    re.IGNORECASE,
)

ERROR_LEAK_PATTERN = re.compile(
    r"(?:internal\s+server\s+error|sql\s+syntax\s+error|"
    r"undefined\s+(?:variable|method|function)|"
    r"null\s*pointer|segmentation\s+fault|"
    r"unhandled\s+exception|fatal\s+error|"
    r"errno|stacktrace|core\s+dump)",
    re.IGNORECASE,
)

# ── Detection Registries ────────────────────────────────────────────────────

SENSITIVE_PATTERNS = {
    "email": EMAIL_PATTERN,
    "phone": PHONE_PATTERN,
    "api_key": API_KEY_PATTERN,
    "password": PASSWORD_PATTERN,
    "token": TOKEN_PATTERN,
    "secret": SECRET_PATTERN,
}

SECURITY_PATTERNS = {
    "xss": XSS_PATTERN,
    "xss_encoded": XSS_ENCODED_PATTERN,
    "sql_injection": SQL_INJECTION_PATTERN,
    "path_traversal": PATH_TRAVERSAL_PATTERN,
    "command_injection": COMMAND_INJECTION_PATTERN,
    "ssrf": SSRF_PATTERN,
    "log4shell": LOG4SHELL_PATTERN,
    "xxe": XXE_PATTERN,
    "rce": RCE_PATTERN,
    "waf_bypass": WAF_BYPASS_PATTERN,
    "open_redirect": OPEN_REDIRECT_PATTERN,
    "ldap_injection": LDAP_INJECTION_PATTERN,
    "idor": IDOR_PATTERN,
    "stack_trace": STACK_TRACE_PATTERN,
    "debug_leak": DEBUG_MODE_PATTERN,
    "hardcoded_credential": HARDCODED_CREDENTIAL_PATTERN,
    "error_leak": ERROR_LEAK_PATTERN,
}

NETWORK_PATTERNS = {
    "syn_flood": SYN_FLOOD_PATTERN,
    "port_scan": PORT_SCAN_PATTERN,
    "arp_spoof": ARP_SPOOF_PATTERN,
    "dns_exfiltration": DNS_EXFIL_PATTERN,
}

LOG_PATTERNS = {
    "failed_login": FAILED_LOGIN_PATTERN,
    "suspicious_ip": SUSPICIOUS_IP_INDICATORS,
}

# ── Risk Mapping ─────────────────────────────────────────────────────────────

RISK_MAP: dict[str, str] = {
    # Sensitive data
    "api_key": "high",
    "password": "critical",
    "token": "high",
    "email": "low",
    "phone": "low",
    "secret": "critical",
    # Web attacks
    "xss": "critical",
    "xss_encoded": "critical",
    "sql_injection": "critical",
    "path_traversal": "high",
    "command_injection": "critical",
    "ssrf": "critical",
    "log4shell": "critical",
    "xxe": "high",
    "rce": "critical",
    "waf_bypass": "critical",
    "open_redirect": "medium",
    "ldap_injection": "high",
    # Code issues
    "stack_trace": "medium",
    "debug_leak": "medium",
    "hardcoded_credential": "critical",
    "error_leak": "medium",
    # Log analysis
    "failed_login": "medium",
    "suspicious_ip": "high",
    "brute_force": "critical",
    # Network
    "syn_flood": "critical",
    "port_scan": "high",
    "arp_spoof": "critical",
    "dns_exfiltration": "high",
}


def url_decode_content(content: str) -> str:
    """Return URL-decoded version of content for encoded payload detection."""
    try:
        return urllib.parse.unquote_plus(content)
    except Exception:
        return content
