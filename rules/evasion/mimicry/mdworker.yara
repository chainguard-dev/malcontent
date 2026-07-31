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
    // The two $not strings are the two halves of one Apple Spotlight version
    // stamp, so only their conjunction identifies the real binary; either half
    // alone is copyable padding.
    $ref and not all of ($not*)
}
