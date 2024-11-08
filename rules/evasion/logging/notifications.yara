rule killall_NotificationCenter: high macos {
  meta:
    description = "kills the macOS NotificationCenter"

  strings:
    $killall = "killall" fullword
    $nc      = "NotificationCenter" fullword

  condition:
    filesize < 1MB and all of them
}
