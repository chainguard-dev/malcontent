rule proc_arbitrary: medium {
  meta:
    description = "access /proc for arbitrary pids"

  strings:
    $ref = /\/proc\/[%{$][\/\$\w\}]{0,12}/

  condition:
    $ref
}

rule pid_match: medium {
  meta:
    description = "scan /proc for matching pids"

  strings:
    $string_val = /\/proc\/\\d[\/\$\w\}]{0,12}/

  condition:
    any of them
}
