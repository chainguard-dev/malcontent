rule http_url_with_exe: high {
  meta:
    description = "accesses hardcoded executable endpoint"

  strings:
    $exe_url         = /https*:\/\/[\w\.]{0,160}[:\/\w\_\-\?\@=]{6,160}\.exe/
    $not_mongodb_404 = "https://docs.mongodb.com/manual/reference/method/Bulk.exe"
    $not_elastic     = "\"license\": \"Elastic License v2\""

  condition:
    any of ($exe*) and none of ($not*)
}

rule http_ip_url_with_exe: critical {
  meta:
    description = "accesses hardcoded executable endpoint via IP"

  strings:
    $exe_url = /https*:\/\/[\d\.\:\[\]]{8,64}[:\/\w\_\-\?\@=]{6,160}\.exe/

    $not_elastic = "\"license\": \"Elastic License v2\""

  condition:
    any of ($exe*) and none of ($not*)
}

rule http_url_with_msi: high {
  meta:
    description = "accesses hardcoded install file endpoint"

  strings:
    $exe_url = /https*:\/\/[\w\.]{0,160}[:\/\w\_\-\?\@=]{6,160}\.msi/

    $not_elastic = "\"license\": \"Elastic License v2\""

  condition:
    any of ($exe*) and none of ($not*)
}

rule http_ip_url_with_msi: critical {
  meta:
    description = "accesses hardcoded install file endpoint via IP"

  strings:
    $exe_url = /https*:\/\/[\d\.\:\[\]]{8,64}[:\/\w\_\-\?\@=]{6,160}\.msi/

    $not_elastic = "\"license\": \"Elastic License v2\""

  condition:
    any of ($exe*) and none of ($not*)
}

rule http_url_with_powershell: high {
  meta:
    description = "accesses hardcoded powershell file endpoint"

  strings:
    $exe_url = /https*:\/\/[\w\.]{0,160}[:\/\w\_\-\?\@=]{6,160}\.ps1/

    $not_elastic = "\"license\": \"Elastic License v2\""

  condition:
    any of ($exe*) and none of ($not*)
}

rule http_ip_url_with_powershell: critical {
  meta:
    description = "accesses hardcoded powershell file endpoint via IP"

  strings:
    $exe_url = /https*:\/\/[\d\.\:\[\]]{8,64}[:\/\w\_\-\?\@=]{6,160}\.ps1/

    $not_elastic = "\"license\": \"Elastic License v2\""

  condition:
    any of ($exe*) and none of ($not*)
}
