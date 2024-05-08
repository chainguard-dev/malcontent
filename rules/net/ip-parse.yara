
rule inet_addr : notable {
  meta:
    pledge = "inet"
    description = "parses IP address"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0fa8a2e98ba17799d559464ab70cce2432f0adae550924e83d3a5a18fe1a9fc8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
    hash_2023_Downloads_2f13 = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
  strings:
    $ref = "inet_addr"
  condition:
    any of them
}

rule inet_pton : notable {
  meta:
    pledge = "inet"
    description = "parses IP address (IPv4 or IPv6)"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2023_Downloads_b56a = "b56a89db553d4d927f661f6ff268cd94bdcfe341fd75ba4e7c464946416ac309"
  strings:
    $ref = "inet_pton"
  condition:
    any of them
}

rule ip_go : notable {
  meta:
    pledge = "inet"
    description = "parses IP address (IPv4 or IPv6)"
    hash_2023_Downloads_21b3 = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
  strings:
    $ref = "IsSingleIP"
    $ref2 = "IsLinkLocalUnicast"
  condition:
    any of them
}
