rule dropper: medium {
  meta:
    description = "References 'dropper'"

  strings:
    $ref  = "dropper" fullword
    $ref2 = "Dropper" fullword

  condition:
    any of them
}

rule dropper_for: high {
  meta:
    description = "References 'dropper for'"

  strings:
    $ref = /[dD]ropper for [\w ]{0,32}/

  condition:
    any of them
}
