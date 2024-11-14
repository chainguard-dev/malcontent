rule macos_window_watcher: high {
  meta:
    hash_2023_JokerSpy_xcc = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"

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
