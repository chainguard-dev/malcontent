rule pid_file: medium {
  meta:
    description = "pid file, likely DIY daemon"

  strings:
    $ref      = /\w{0,16}pidFile{0,16}/
    $ref2     = /\w{0,16}PidFile{0,16}/
    $ref3     = /\w{0,16}pid_file{0,16}/
    $ref4     = /[\/\~][\w\/]{0,32}\.pid/
    $not_klog = "/klog/v2.pid"

  condition:
    any of ($ref*) and none of ($not*)
}
