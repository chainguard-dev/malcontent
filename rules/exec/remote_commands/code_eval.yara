rule eval: medium {
  meta:
    description = "evaluate code dynamically using eval()"

  strings:
    $val       = /eval\([a-zA-Z\"\'\(\,\)]{1,32}/ fullword
    $val2      = "eval(this.toString());"
    $not_empty = "eval()"

  condition:
    filesize < 1MB and any of ($val*) and none of ($not*)
}

rule python_exec: medium {
  meta:
    description = "evaluate code dynamically using exec()"

  strings:
    $import = "import" fullword
    $val    = /exec\([a-z\"\'\(\,\)]{1,32}/ fullword
    $empty  = "exec()"

  condition:
    filesize < 1MB and $import and $val and not $empty
}

rule shell_eval: medium {
  meta:
    description = "evaluate shell code dynamically using eval"

  strings:
    $val                 = /eval \$\w{0,64}/ fullword
    $not_fish_completion = "fish completion"

  condition:
    $val and none of ($not*)
}

rule php_create_function_no_args: high {
  meta:
    description = "dynamically creates PHP functions without arguments"

  strings:
    $val = /create_function\([\'\"]{2},\$/

  condition:
    any of them
}

rule php_at_eval: critical {
  meta:
    description = "evaluates code in a way that suppresses errors"

  strings:
    $at_eval   = /@\beval\s{0,32}\(\s{0,32}(\$\w{0,32}|\.\s{0,32}"[^"]{0,32}"|\.\s{0,32}'[^']{0,32}'|\w+\(\s{0,32}\))/
    $not_empty = "eval()"

  condition:
    $at_eval and none of ($not*)
}

rule npm_preinstall_eval: critical {
  meta:
    description = "NPM preinstall evaluates arbitrary code"

  strings:
    $ref = /\s{2,8}"preinstall": ".{12,256}eval\([\w\.]{1,32}\).{0,256}"/

  condition:
    filesize < 1KB and $ref
}
