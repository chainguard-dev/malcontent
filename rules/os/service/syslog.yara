rule syslog: harmless {
  meta:
    description = "Use the syslog (system log) service"
    // The truth is a bit more nuanced
    capability  = "CAP_SYSLOG"

  strings:
    $ref = "syslog" fullword

  condition:
    all of them
}
