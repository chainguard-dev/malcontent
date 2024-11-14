rule systemctl_calls_val: medium {
  meta:
    description = "makes calls to systemctl"

  strings:
    $systemctl_cmd = /systemctl (daemon-reload|reload|enable|stop|disable|restart|start)[\w _-]{0,32}/

  condition:
    any of them
}
