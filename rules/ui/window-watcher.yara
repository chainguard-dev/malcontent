
rule macos_window_watcher : high {
  meta:
    hash_2023_JokerSpy_xcc = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
    hash_2023_JokerSpy_xcc_2 = "951039bf66cdf436c240ef206ef7356b1f6c8fffc6cbe55286ec2792bf7fe16c"
    hash_2023_JokerSpy_xcc_3 = "6d3eff4e029db9d7b8dc076cfed5e2315fd54cb1ff9c6533954569f9e2397d4c"
  strings:
    $w_cglocked = "CGSSessionScreenIsLocked"
    $w_idle = "HIDIdleTime"
    $w_frontmost = "frontmostApplication"
    $w_proc = "processIdentifier"
    $not_xul = "XUL_APP_FILE"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_grammarly = "ProjectLlama"
    $not_slack = "Slack Technologies"
    $not_arc = "WelcomeToArc"
  condition:
    2 of ($w_*) and none of ($not*)
}
