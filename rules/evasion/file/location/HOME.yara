rule custom_home: medium linux {
  meta:
    description = "overrides the HOME directory environment variable"

  strings:
    $ref      = /HOME=\/[a-z][\.\w\/]{0,24}/ fullword
    $not_root = "HOME=/root"

  condition:
    $ref and none of ($not*)
}
