rule mdworker: medium {
  meta:
    description = "references mdmorker, may masquerade as it on macOS"

  strings:
    $ref = "mdworker" fullword

  condition:
    $ref
}

rule mdworker_high: high {
  meta:
    description = "references mdmorker, may masquerade as it on macOS"

  strings:
    $ref         = "mdworker" fullword
    $not_program = "@(#)PROGRAM:md"
    $not_proj    = "PROJECT:Spotlight"

  condition:
    $ref and none of ($not*)
}
