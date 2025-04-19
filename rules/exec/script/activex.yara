import "math"

rule ActiveXObject: medium windows {
  meta:
    description = "Create an ActiveX object"

  strings:
    $ActiveXObject = "ActiveXObject"

  condition:
    any of them
}

rule ActiveXObject_obfuscated_var: high windows {
  meta:
    description = "Invokes obfuscated ActiveX object"

  strings:
    $ref = /ActiveXObject\(\w{0,3}\(0x\w{0,3}\)\)/

  condition:
    any of them
}

rule ActiveXObject_obfuscated_split: critical windows {
  meta:
    description = "Invokes obfuscated ActiveX object"

  strings:
    $ref = /ActiveXObject\(\w{0,16}\.split.{0,128}\.join.{0,8}/

  condition:
    any of them
}

rule ActiveXObject_obfuscated_fromCharCode: high windows {
  meta:
    description = "Invokes obfuscated ActiveX object"

  strings:
    $activex  = "ActiveXObject("
    $fromchar = "fromCharCode("

  condition:
    filesize < 128KB and all of them and math.abs(@activex - @fromchar) > 64
}
