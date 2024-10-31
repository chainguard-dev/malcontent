rule sigaction_SIGQUIT: harmless {
  meta:
    description = "Listen for SIGQUIT (kill) events"

  strings:
    $sigaction = "sigaction" fullword
    $sigalrm   = "QUIT"

  condition:
    all of them
}
