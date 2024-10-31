rule var_log_install: high {
  meta:
    description = "accesses software installation logs"

  strings:
    $ref = "/var/log/install.log" fullword

  condition:
    $ref
}
