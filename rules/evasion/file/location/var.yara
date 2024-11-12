rule var_hidden: high {
  meta:
    description = "path reference to hidden file within /var"

  strings:
    $ref = /\/var\/\.[%\w\.\-\/]{0,64}/ fullword

    $not_updated = "/var/.updated" fullword

  condition:
    $ref and none of ($not*)
}
