
rule vnc_user : notable {
  strings:
    $vnc_password = "vnc_password"
    $vnc_ = "VNC_"
    $vnc_port = ":5900"
    $not_synergy = "SYNERGY"
  condition:
    any of ($vnc*) and none of ($not*)
}
