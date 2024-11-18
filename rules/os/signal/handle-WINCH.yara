rule sigaction_WINCH: harmless {
  meta:
    description = "Listen for SIGWINCH (terminal window change) events"

  strings:
    $sigaction = "sigaction" fullword
    $sigalrm   = "WINCH"

  condition:
    all of them
}
