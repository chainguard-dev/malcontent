rule sigaction_ALRM: harmless {
  meta:
    description = "Listen for SIGALRM (timeout) events"

  strings:
    $sigaction = "sigaction" fullword
    $sigalrm   = "ALRM"

  condition:
    all of them
}
