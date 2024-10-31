rule notification_dialog_with_sysctl_and_curl {
  meta:
    description = "Shows an alert dialog"

  strings:
    $ref = "CFUserNotificationDisplayAlert"

  condition:
    $ref
}
