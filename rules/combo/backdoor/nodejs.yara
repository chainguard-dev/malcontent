
rule timeout_eval : critical {
  meta:
    description = "evaluate code dynamically using eval() after timeout"
    hash_2023_package_bgService = "36831e715a152658bab9efbd4c2c75be50ee501b3dffdb5798d846a2259154a2"
  strings:
    $ref = /setTimeout\(.{0,64}eval\([\w\(\,\)\;\*\}]{0,32}/ fullword
  condition:
    any of them
}
