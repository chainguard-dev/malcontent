rule php_no_time_limit: medium {
  meta:
    description = "disables execution time limit"

  strings:
    $ref = "set_time_limit(0)"

  condition:
    $ref
}
