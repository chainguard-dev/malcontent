rule generic_launchctl_loader: high {
  meta:
    hash_2020_BirdMiner_tormina = "4179cdef4de0eef44039e9d03d42b3aeca06df533be74fc65f5235b21c9f0fb1"

  strings:
    $load        = /launchctl load [\- \~\w\.\/]{1,128}\.plist/
    $not_osquery = "OSQUERY_WORKER"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_kandji  = "com.kandji.profile.mdmprofile"
    $not_apple   = "/System/Library/LaunchDaemons/com.apple"

  condition:
    $load and none of ($not_*)
}
