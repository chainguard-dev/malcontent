
rule systemctl_calls_val : notable {
  strings:
    $systemctl_cmd = /systemctl (daemon-reload|reload|enable|stop|disable|restart|start)[\w _-]{0,32}/
  condition:
    any of them
}
