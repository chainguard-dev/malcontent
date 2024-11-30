rule dropper: medium {
  meta:
    description = "References a 'dropper'"

  strings:
    $ref = /[\w]{0,16}[dD]ropper/ fullword

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
