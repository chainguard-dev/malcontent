import "math"

rule eval: medium {
  meta:
    description = "evaluate code dynamically using eval()"

  strings:
    $val       = /eval\([\.\+ _a-zA-Z\"\'\(\,\)]{1,32}/ fullword
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
    $val    = /exec\([\w\ \"\'\.\(\)\[\]]{1,64}/ fullword
    $empty  = "exec()"

  condition:
    filesize < 1MB and $import and $val and not $empty
}

rule python_exec_near_enough_chr: high {
  meta:
    description = "Likely executes encoded character content"

  strings:
    $exec = "exec("
    $chr  = "chr("

  condition:
    all of them and math.abs(@chr - @exec) < 100
}

rule python_exec_near_enough_fernet: high {
  meta:
    description = "Likely executes Fernet encrypted content"

  strings:
    $exec   = "exec("
    $fernet = "Fernet("

  condition:
    all of them and math.abs(@exec - @fernet) < 100
}

rule python_exec_near_enough_decrypt: high {
  meta:
    description = "Likely executes encrypted content"

  strings:
    $exec   = "exec("
    $fernet = "decrypt("

  condition:
    all of them and math.abs(@exec - @fernet) < 100
}

rule python_exec_chr: critical {
  meta:
    description = "Executes encoded character content"

  strings:
    $exec = /exec\(.{0,16}chr\(.{0,16}\[\d[\d\, ]{0,64}/

  condition:
    filesize < 512KB and all of them
}

rule python_exec_bytes: critical {
  meta:
    description = "Executes a transformed bytestream"

  strings:
    $exec = /exec\([\w\.\(]{0,16}\(b['"].{8,16}/

  condition:
    filesize < 512KB and all of them
}

rule python_exec_complex: high {
  meta:
    description = "Executes code from a complex expression"

  strings:
    $exec           = /exec\([\w\. =]{1,32}\(.{0,8192}\)\)/ fullword
    $not_javascript = "function("
    $not_pyparser   = "exec(compile(open(self.parsedef).read(), self.parsedef, 'exec'))"

  condition:
    filesize < 512KB and $exec and none of ($not*)
}

rule python_exec_fernet: critical {
  meta:
    description = "Executes Fernet encrypted content"

  strings:
    $exec = /exec\(.{0,16}Fernet\(.{0,64}/

  condition:
    filesize < 512KB and all of them
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
