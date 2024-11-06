rule tcap: medium {
  meta:
    description = "handles TCAP (Transaction Capabilities Application Part) messages"

  strings:
    $send = "tcap"
    $imsi = "imsi"

  condition:
    filesize < 2MB and all of them
}
