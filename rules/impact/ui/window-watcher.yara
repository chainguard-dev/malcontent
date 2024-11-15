rule macos_window_watcher: high {
  meta:
    description = "watches what graphical applications are in use"

  strings:
    $w_cglocked    = "CGSSessionScreenIsLocked"
    $w_idle        = "HIDIdleTime"
    $w_frontmost   = "frontmostApplication"
    $w_proc        = "processIdentifier"
    $not_xul       = "XUL_APP_FILE"
    $not_private   = "/System/Library/PrivateFrameworks/"
    $not_grammarly = "ProjectLlama"
    $not_slack     = "Slack Technologies"
    $not_arc       = "WelcomeToArc"

  condition:
    2 of ($w_*) and none of ($not*)
}
