rule php_no_time_limit: medium {
  meta:
    description = "disables execution time limit"
    filetypes   = "php"

  strings:
    $ref = "set_time_limit(0)"

  condition:
    $ref
}
