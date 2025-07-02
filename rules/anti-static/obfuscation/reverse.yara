rule string_reversal: medium {
  meta:
    description = "reverses strings"
    filetypes   = "py"

  strings:
    $ref = ".reverse().join(\"\")"

  condition:
    any of them
}

rule js_function_reversal: high {
  meta:
    description = "reversed javascript function calls"
    filetypes   = "js,ts"

  strings:
    $function_rev1 = "noitcnuf"
    $function_rev2 = { 6E 6F 69 74 63 6E 75 66 }

    $function_dots = /no\.?i\.?t\.?c\.?n\.?u\.?f/
    $return_rev    = "nruter"
    $return_dots   = /nr\.?u\.?t\.?e\.?r/

  condition:
    filesize < 1MB and (
      ($function_rev1 or $function_rev2) and ($return_rev or $return_dots) or
      ($function_dots and $return_dots)
    )
}
