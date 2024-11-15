rule generic_launchctl_loader: high {
  meta:
    description = "loads a launchd service"

  strings:
    $load        = /launchctl load [\- \~\w\.\/]{1,128}\.plist/
    $not_osquery = "OSQUERY_WORKER"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_kandji  = "com.kandji.profile.mdmprofile"
    $not_apple   = "/System/Library/LaunchDaemons/com.apple"

  condition:
    $load and none of ($not_*)
}
