rule hacktool_mimikatz: critical {
  meta:
    description = "extract Windows passwords from memory"

  strings:
    // extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
    $passwords = "sekurlsa::logonpasswords" ascii wide nocase
    $error     = "ERROR kuhl" wide xor

  condition:
    any of them
}
