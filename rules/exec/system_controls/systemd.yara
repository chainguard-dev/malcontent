rule systemctl_calls_val: medium {
  meta:
    description = "makes calls to systemctl"

  strings:
    $systemctl_cmd = /systemctl.{1,2048}(daemon-reload|reload|enable|stop|disable|restart|start)[\w _-]{0,32}/

  condition:
    any of them
}

rule ref_systemd: low {
  meta:
    description = "makes references to systemd"

  strings:
    $systemd = "systemd" fullword
    $SYSTEMD = "SYSTEMD" fullword

  condition:
    any of them
}
