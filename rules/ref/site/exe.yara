
rule http_url_with_exe : high {
  meta:
    description = "accesses hardcoded executable endpoint"
  strings:
    $exe_url = /https*:\/\/[\w\.]{0,160}[:\/\w\_\-\?\@=]{6,160}\.exe/ fullword
  condition:
    any of ($exe*)
}

rule http_ip_url_with_exe : critical {
  meta:
    description = "accesses hardcoded executable endpoint via IP"
  strings:
    $exe_url = /https*:\/\/[\d\.\:\[\]]{8,64}[:\/\w\_\-\?\@=]{6,160}\.exe/ fullword
  condition:
    any of ($exe*)
}

