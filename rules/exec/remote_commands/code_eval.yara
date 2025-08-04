import "math"

rule js_eval: medium {
  meta:
    description = "evaluate code dynamically using eval()"
    filetypes   = "js,ts"

  strings:
    $val       = /eval\([\.\+ _a-zA-Z\"\'\(\,\)]{1,32}/ fullword
    $val2      = "eval(this.toString());"
    $not_empty = "eval()"

  condition:
    filesize < 1MB and any of ($val*) and none of ($not*)
}

rule js_eval_fx_str: high {
  meta:
    description = "evaluate processed string using eval()"
    filetypes   = "js,ts"

  strings:
    $val = /eval\(\w{0,16}\([\"\'].{0,16}/

  condition:
    filesize < 1MB and any of ($val*)
}

rule js_eval_fx_str_multiple: critical {
  meta:
    description = "multiple evaluations of processed string using eval()"
    filetypes   = "js,ts"

  strings:
    $val = /eval\(\w{0,16}\([\"\'].{0,16}/

  condition:
    filesize < 1MB and #val > 1
}

rule js_eval_response: critical {
  meta:
    description = "executes code directly from HTTP response"
    filetypes   = "js,ts"

  strings:
    $val = /eval\(\w{0,16}\.responseText\)/

    $not_dojo = /dojo(\-|\_|x)/
    $not_ejs  = /EJS\.|EJS=/

  condition:
    filesize < 1MB and any of ($val*) and not #not_ejs > 0 and not #not_dojo > 0
}

rule js_eval_near_enough_fromChar: medium {
  meta:
    description = "Evaluates content via String.fromCharCode"
    filetypes   = "js,ts"

  strings:
    $eval    = /[\s\{]eval\(/
    $decrypt = "String.fromCharCode"

  condition:
    filesize < 5MB and all of them and math.abs(@eval - @decrypt) > 384
}

rule js_eval_obfuscated_fromChar: high {
  meta:
    description = "Likely evaluates encrypted content via fromCharCode"
    filetypes   = "js,ts"

  strings:
    $eval = /[\s\{]eval\(/
    $ref  = /fromCharCode\(\w{0,16}\s{0,2}[\-\+\*\^]{0,2}\w{0,16}/

    $not_elastic1 = "/*! Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one or more contributor license agreements."
    $not_elastic2 = "* Licensed under the Elastic License 2.0; you may not use this file except in compliance with the Elastic License 2.0. */"

  condition:
    filesize < 5MB and all of them and math.abs(@eval - @ref) > 384 and none of ($not*)
}

rule js_anonymous_function: medium {
  meta:
    description = "evaluates code using an anonymous function"
    filetypes   = "js,ts"

  strings:
    $func = /\n\s{0,8}\(function\s{0,8}\(\)\s{0,8}\{/
    $run  = /\n\s{0,8}\}\)\(\);/

  condition:
    filesize < 5MB and all of them and (@run - @func) > 384
}

rule python_exec: medium {
  meta:
    description = "evaluate code dynamically using exec()"
    filetypes   = "py"

  strings:
    $f_import = "import" fullword
    $f_join   = ".join("
    $f_chr    = "chr("
    $f_int    = "int("
    $f_for    = /for [a-z] in /
    $val      = /exec\([\w\ \"\'\.\(\)\[\]]{1,64}/ fullword
    $empty    = "exec()"

  condition:
    filesize < 1MB and any of ($f*) and $val and not $empty
}

rule python_exec_near_enough_chr: high {
  meta:
    description = "Likely executes encoded character content"
    filetypes   = "py"

  strings:
    $exec = "exec("
    $chr  = "chr("

  condition:
    all of them and math.abs(@chr - @exec) < 768
}

rule python_exec_near_enough_fernet: high {
  meta:
    description = "Likely executes Fernet encrypted content"
    filetypes   = "py"

  strings:
    $exec   = "exec("
    $fernet = "Fernet("

  condition:
    all of them and math.abs(@exec - @fernet) < 768
}

rule python_exec_near_enough_decrypt: high {
  meta:
    description = "Likely executes encrypted content"
    filetypes   = "py"

  strings:
    $exec    = /\bexec\(/
    $decrypt = "decrypt("

  condition:
    all of them and math.abs(@exec - @decrypt) < 768
}

rule python_exec_chr: critical {
  meta:
    description = "Executes encoded character content"
    filetypes   = "py"

  strings:
    $exec = /exec\(.{0,16}chr\(.{0,16}\[\d[\d\, ]{0,64}/

  condition:
    filesize < 512KB and all of them
}

rule python_exec_bytes: critical {
  meta:
    description = "Executes a transformed bytestream"
    filetypes   = "py"

  strings:
    $exec = /exec\([\w\.\(]{0,16}\(b['"].{8,16}/

  condition:
    filesize < 512KB and all of them
}

rule python_exec_complex: high {
  meta:
    description = "Executes code from a complex expression"
    filetypes   = "py"

  strings:
    $exec           = /exec\([\w\. =]{1,32}\(.{0,8192}\)\)/ fullword
    $not_javascript = "function("
    $not_pyparser   = "exec(compile(open(self.parsedef).read(), self.parsedef, 'exec'))"
    $not_versioneer = "exec(VERSIONEER.decode(), globals())"

  condition:
    filesize < 512KB and $exec and none of ($not*)
}

rule python_exec_fernet: critical {
  meta:
    description = "Executes Fernet encrypted content"
    filetypes   = "py"

  strings:
    $exec = /exec\(.{0,16}Fernet\(.{0,64}/

  condition:
    filesize < 512KB and all of them
}

rule shell_eval: medium {
  meta:
    description = "evaluate shell code dynamically using eval"
    filetypes   = "bash,sh,zsh"

  strings:
    $val                 = /eval \$\w{0,64}/ fullword
    $not_fish_completion = "fish completion"

  condition:
    $val and none of ($not*)
}

rule php_create_function_no_args: high {
  meta:
    description = "dynamically creates PHP functions without arguments"
    filetypes   = "php"

  strings:
    $val = /create_function\([\'\"]{2},\$/

  condition:
    any of them
}

rule php_at_eval: critical {
  meta:
    description = "evaluates code in a way that suppresses errors"
    filetypes   = "php"

  strings:
    $at_eval      = /@\beval\s{0,32}\(\s{0,32}(\$\w{0,32}|\.\s{0,32}"[^"]{0,32}"|\.\s{0,32}'[^']{0,32}'|\w+\(\s{0,32}\))/
    $not_empty    = "eval()"
    $not_phpunit1 = "This file is part of PHPUnit."
    $not_phpunit2 = "(c) Sebastian Bergmann <sebastian@phpunit.de>"

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
