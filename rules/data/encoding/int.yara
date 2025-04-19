rule js_parseInt: low {
  meta:
    description = "parses integers"

  strings:
    $ref = "parseInt("

  condition:
    any of them
}

rule js_parseInt_Math: medium {
  meta:
    description = "performs math directly against parsed integers"

  strings:
    $ref = /[\^\*\-\+]\s{0,2}parseInt\(/

  condition:
    any of them
}
