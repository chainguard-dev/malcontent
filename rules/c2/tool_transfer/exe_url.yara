rule http_url_with_exe: high {
  meta:
    description = "accesses hardcoded executable endpoint"

  strings:
    $exe_url         = /https*:\/\/[\w\.]{0,160}[:\/\w\_\-\?\@=]{6,160}\.exe/
    $not_mongodb_404 = "https://docs.mongodb.com/manual/reference/method/Bulk.exe"

  condition:
    any of ($exe*) and none of ($not*)
}

rule http_ip_url_with_exe: critical {
  meta:
    description = "accesses hardcoded executable endpoint via IP"

  strings:
    $exe_url = /https*:\/\/[\d\.\:\[\]]{8,64}[:\/\w\_\-\?\@=]{6,160}\.exe/

  condition:
    any of ($exe*)
}

rule http_url_with_msi: high {
  meta:
    description = "accesses hardcoded install file endpoint"

  strings:
    $exe_url = /https*:\/\/[\w\.]{0,160}[:\/\w\_\-\?\@=]{6,160}\.msi/

  condition:
    any of ($exe*)
}

rule http_ip_url_with_msi: critical {
  meta:
    description = "accesses hardcoded install file endpoint via IP"

  strings:
    $exe_url = /https*:\/\/[\d\.\:\[\]]{8,64}[:\/\w\_\-\?\@=]{6,160}\.msi/

  condition:
    any of ($exe*)
}

