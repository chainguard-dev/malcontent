rule js_while_true_obfuscation: medium {
  meta:
    description = "obfuscated 'while true' loop"
    filetypes   = "application/javascript"

  strings:
    $ref  = "while (!![])"
    $ref2 = "while(!![])"

  condition:
    any of them
}
