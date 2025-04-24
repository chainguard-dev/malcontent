private rule reverse_probably_js {
  strings:
    $f_function  = /function\(\w{0,8}\)/
    $f_const     = /\bconst\s/
    $f_return    = /\breturn\s/
    $f_var       = /\bvar\s/
    $f_Array     = "Array.prototype" fullword
    $f_true      = "true);"
    $f_false     = "false);"
    $f_run       = ".run("
    $f_Run       = ".Run("
    $f_Object    = "Object."
    $f_async     = "async function"
    $f_await     = "await"
    $f_this      = "this."
    $f_prototype = ".prototype"

    $not_asyncio = "await asyncio"

  condition:
    filesize < 3MB and 3 of them and none of ($not*)
}

rule string_reversal: medium {
  meta:
    description = "reverses strings"

  strings:
    $ref = ".reverse().join(\"\")"

  condition:
    any of them
}

rule function_reversal: high {
  meta:
    description = "reversed function definition"

  strings:
    $ref = /n.{0,3}o.{0,3}i.{0,3}t.{0,3}c.{0,3}n.{0,3}u.{0,3}f/

  condition:
    filesize < 1MB and any of them
}

rule js_reversal: critical {
  meta:
    description = "multiple reversed javascript calls"

  strings:
    $ref  = /n.{0,3}o.{0,3}i.{0,3}t.{0,3}c.{0,3}n.{0,3}u.{0,3}f/
    $ref2 = /n.{0,3}r.{0,3}u.{0,3}t.{0,3}e.{0,3}r/

  condition:
    reverse_probably_js and filesize < 1MB and all of them
}
