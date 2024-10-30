rule tls_dp_port: critical {
  meta:
    description = "contains cryptominer command-line"

  strings:
    $ref = /-p \d+ -tls -dp \d+/

  condition:
    any of them
}
