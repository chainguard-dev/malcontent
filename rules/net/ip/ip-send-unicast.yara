rule unicast {
  meta:
    pledge      = "inet"
    description = "send data to the internet"

  strings:
    $unicast = "unicast" fullword

  condition:
    any of them
}
