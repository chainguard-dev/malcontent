// Private rule for LOLBAS system information gathering tools detection
// These patterns are reused across multiple threat and capability rules

private rule lolbas_sysinfo
{
    strings:
        // Require the sysinfo command to appear as the argument of an exec call,
        // so dict keys (result['hostname']), XML lookups (findall("hostname"))
        // and API paths (/workers/whoami) no longer match.
        $whoami = /\b(popen|system|getoutput|getstatusoutput|check_output|check_call|Popen|run|call|spawn\w*|execl?p?e?|exec_command)\s*\(\s*\[?\s*['"]whoami\b/ nocase
        $hostname = /\b(popen|system|getoutput|getstatusoutput|check_output|check_call|Popen|run|call|spawn\w*|execl?p?e?|exec_command)\s*\(\s*\[?\s*['"]hostname\b/ nocase

    condition:
        any of them
}

rule threat_process_sysinfo
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects LOLBAS usage in process spawning"
        identifies = "threat.process.spawn.sysinfo"
        severity = "medium"
        mitre_tactics = "collection"
        specificity = "medium"
        sophistication = "low"

        max_hits = 5
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    condition:
        lolbas_sysinfo
}
