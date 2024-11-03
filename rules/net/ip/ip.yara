rule packets {
  meta:
    pledge      = "inet"
    description = "access the internet"

  strings:
    $invalid_packet = "invalid packet" fullword

  condition:
    any of them
}
