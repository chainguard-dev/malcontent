rule heartbeat: medium {
  meta:
    description = "references a 'heartbeat'"

  strings:
    $ref  = /[\w \:]{0,32}[hH]eart[bB]eat[\w\: ]{0,8}/
    $ref2 = /[\w \:]{0,32}[bB]eat[hH]eart[\w\: ]{0,8}/

  condition:
    any of ($ref*)
}
