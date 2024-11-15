rule killed_all: medium {
  meta:
    description = "References 'killed all'"

  strings:
    $ref = /killed all[\w ]+/

  condition:
    any of them
}

rule killed_format: medium {
  meta:
    description = "References 'killed %d'"

  strings:
    $ref = /[Kk]illed %d/

  condition:
    any of them
}
