rule ip_spoof: high {
  meta:
    pledge      = "inet"
    description = "spoof IP addresses"

  strings:
    $ip_spoof = "ipspoof" fullword

  condition:
    any of them
}
