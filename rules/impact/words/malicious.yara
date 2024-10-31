rule malicious : medium {
  meta:
    description = "References 'malicious'"
  strings:
    $ref = /[a-zA-Z\-_ ]{0,16}malicious[a-zA-Z\-_ ]{0,16}/ fullword
  condition:
    any of them
}

rule malici0us : high {
  meta:
    description = "References 'malici0us'"
  strings:
    $ref = /[a-zA-Z\-_ ]{0,16}malici0us[a-zA-Z\-_ ]{0,16}/ fullword
  condition:
    any of them
}
