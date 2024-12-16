rule systemd_disabler: medium {
  meta:
    description = "disables systemd services"

  strings:
    $ref = "systemctl disable"

  condition:
    filesize < 10MB and any of them
}

rule systemd_disabler_high: high {
  meta:
    description = "disables arbitrary systemd services, hiding output"

  strings:
    $ref = "systemctl disable %s 2>/dev/null"

  condition:
    filesize < 10MB and any of them
}
