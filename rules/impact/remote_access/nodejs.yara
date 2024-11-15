rule timeout_eval: critical {
  meta:
    description = "evaluate code dynamically using eval() after timeout"

  strings:
    $ref = /setTimeout\(.{0,64}eval\([\w\(\,\)\;\*\}]{0,32}/ fullword

  condition:
    any of them
}
