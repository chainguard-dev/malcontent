rule var_log_path: medium {
  meta:
    description = "path reference within /var/log"

  strings:
    $ref = /\/var\/log\/[\%\w\.\-\/]{4,32}/ fullword

  condition:
    $ref
}
