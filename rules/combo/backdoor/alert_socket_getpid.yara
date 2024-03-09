
rule notification_dialog_with_sysctl_and_curl {
  meta:
    hash_2023_KandyKorn_log = "3ea2ead8f3cec030906dcbffe3efd5c5d77d5d375d4a54cca03bfe8a6cb59940"
  strings:
    $f_display_alert = "CFUserNotificationDisplayAlert"
    $f_socket = "socket"
    $f_sysctl = "sysctl"
    $f_getpid = "getpid"
    $f_curl = "curl"
	$not_microsoft = "Microsoft Corporation"
  condition:
    all of ($f*) and none of ($not*)
}