rule sigaction_SIGHUP: harmless {
  meta:
    description = "Listen for SIGHUP (hangup) events"

  strings:
    $sigaction = "sigaction" fullword
    $sigalrm   = "HUP"

  condition:
    all of them
}
