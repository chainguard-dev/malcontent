rule iptables_upload_http: medium {
  meta:
    description = "uploads, uses iptables and HTTP"

  strings:
    $ref1 = /upload[a-zA-Z]{0,16}/
    $ref2 = "HTTP" fullword
    $ref3 = /iptables[ \-a-z]{0,16}/

  condition:
    all of them
}

rule iptables_ssh: medium {
  meta:
    description = "Supports iptables and ssh"

  strings:
    $ref3 = /iptables[ \-a-z]{0,16}/
    $ssh  = "ssh" fullword

  condition:
    all of them
}

rule iptables_gdns_http: medium {
  meta:
    description = "Uses iptables, Google Public DNS, and HTTP"

  strings:
    $ref1 = /iptables[ \-a-z]{0,16}/ fullword
    $ref2 = "8.8.8.8" fullword
    $ref3 = "HTTP" fullword

  condition:
    all of them
}
