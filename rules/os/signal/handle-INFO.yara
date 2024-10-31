rule sigaction_SIGINFO: harmless {
  meta:
    description = "Listen for SIGINFO (information) events"

  strings:
    $sigaction = "sigaction" fullword
    $sigalrm   = "SIGINFO"

  condition:
    all of them
}
