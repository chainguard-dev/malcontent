rule iptables_upload_http: medium {
  meta:
    description                   = "uploads, uses iptables and HTTP"
    hash_2023_0xShell_wesoori     = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2024_Downloads_8907      = "89073097e72070cc7cc73c178447b70e07b603ccecfe406fe92fe9eafaae830f"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"

  strings:
    $ref1 = /upload[a-zA-Z]{0,16}/
    $ref2 = "HTTP" fullword
    $ref3 = /iptables[ \-a-z]{0,16}/

  condition:
    all of them
}

rule iptables_ssh: medium {
  meta:
    description                          = "Supports iptables and ssh"
    hash_2023_Downloads_6e35             = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2024_Downloads_e100             = "e100be934f676c64528b5e8a609c3fb5122b2db43b9aee3b2cf30052799a82da"
    hash_2023_Linux_Malware_Samples_1f94 = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"

  strings:
    $ref3 = /iptables[ \-a-z]{0,16}/
    $ssh  = "ssh" fullword

  condition:
    all of them
}

rule iptables_gdns_http: medium {
  meta:
    description                          = "Uses iptables, Google Public DNS, and HTTP"
    hash_2024_Downloads_8907             = "89073097e72070cc7cc73c178447b70e07b603ccecfe406fe92fe9eafaae830f"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
    hash_2023_Linux_Malware_Samples_1f94 = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"

  strings:
    $ref1 = /iptables[ \-a-z]{0,16}/ fullword
    $ref2 = "8.8.8.8" fullword
    $ref3 = "HTTP" fullword

  condition:
    all of them
}
