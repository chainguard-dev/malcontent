rule string_reversal: medium {
  meta:
    description = "reverses strings"
    filetypes   = "py"

  strings:
    $ref = ".reverse().join(\"\")"

  condition:
    any of them
}

rule function_reversal: high {
  meta:
    description = "reversed function definition"
    filetypes   = "js,ts"

  strings:
    $ref = /n.{0,3}o.{0,3}i.{0,3}t.{0,3}c.{0,3}n.{0,3}u.{0,3}f/

  condition:
    filesize < 1MB and any of them
}

rule js_reversal: high {
  meta:
    description = "multiple reversed javascript calls"
    filetypes   = "js,ts"

  strings:
    $ref  = /n.{0,3}o.{0,3}i.{0,3}t.{0,3}c.{0,3}n.{0,3}u.{0,3}f/
    $ref2 = /n.{0,3}r.{0,3}u.{0,3}t.{0,3}e.{0,3}r/

  condition:
    filesize < 1MB and all of them
}
