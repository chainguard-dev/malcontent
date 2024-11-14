rule timeout_eval: critical {
  meta:
    description = "evaluate code dynamically using eval() after timeout"

    hash_1985_package_svc = "7e9492e670d5b0552b62c9bccbd5325609ebaa31bbeaa56953c692b4d970a777"
    hash_1985_package_sv  = "6876fe8c752aae93650ac914735b21361b01aafb19a2a9ed5a7c736174d3ddbe"

  strings:
    $ref = /setTimeout\(.{0,64}eval\([\w\(\,\)\;\*\}]{0,32}/ fullword

  condition:
    any of them
}
