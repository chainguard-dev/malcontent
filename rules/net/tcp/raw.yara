rule tcpraw: medium {
  meta:
    description = "Supports raw TCP packets"

  strings:
    $tcpraw = "tcpraw" fullword

  condition:
    filesize < 10MB and any of them
}
