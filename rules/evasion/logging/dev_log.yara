rule full: medium linux {
  meta:
    description = "device where local syslog messages are read"

  strings:
    $val = "/dev/log" fullword

  condition:
    $val
}
