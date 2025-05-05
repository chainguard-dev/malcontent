rule raise_hard_error: medium windows {
  meta:
    description = "crashes (bluescreens) the machine"
    filetypes   = "text/x-python,application/octet-stream,application/vnd.microsoft.portable-executable"

  strings:
    $crash = "NtRaiseHardError" fullword

  condition:
    filesize < 1MB and any of them
}
