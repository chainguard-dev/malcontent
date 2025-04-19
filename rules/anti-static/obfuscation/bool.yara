rule js_while_true_obfuscation: medium {
  meta:
    description = "obfuscated 'while true' loop"

  strings:
    $ref  = "while (!![])"
    $ref2 = "while(!![])"

  condition:
    any of them
}
