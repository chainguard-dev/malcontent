import "math"

private rule eval_probably_js {
  strings:
    $f_Array     = "Array.prototype" fullword
    $f_async     = "async function"
    $f_await     = "await"
    $f_catch     = "} catch"
    $f_class     = "@class"
    $f_const     = /\bconst\s/
    $f_define    = "define("
    $f_false     = "false);"
    $f_function  = /function\(\w{0,32}\)/
    $f_function2 = "function()"
    $f_function3 = "function ()"
    $f_global    = "global["
    $f_method    = "@method"
    $f_namespace = "@namespace"
    $f_Object    = "Object."
    $f_param     = "@param"
    $f_private   = "@private"
    $f_promise   = "Promise"
    $f_prototype = ".prototype"
    $f_require   = "require("
    $f_return    = /\breturn\s/
    $f_Run       = ".Run("
    $f_run       = ".run("
    $f_strict    = " === "
    $f_this      = "this."
    $f_this2     = "this["
    $f_true      = "true);"
    $f_try       = "try {"
    $f_var       = /\bvar\s/

    $not_asyncio           = "await asyncio"
    $not_class             = /class \w{1,32}\(/ fullword
    $not_def               = /def [a-zA-Z_][a-zA-Z0-9_]{1,32} \(/ ascii
    $not_equals_comment    = "// ==="
    $not_error             = "err error"
    $not_header            = /^#ifndef\s/
    $not_header2           = /^#define\s/
    $not_header3           = /^#include\s/
    $not_import            = /^import \(/
    $not_package           = /^package\s/
    $not_self_assert_equal = "self.assertEqual("
    $not_struct            = /^type \w{1,32} struct \{/ fullword
    $not_typedef           = "typedef typename"

  condition:
    filesize < 5MB and 4 of ($f*) and none of ($not*)
}

private rule eval_probably_python {
  strings:
    $import       = "import "
    $f_common     = /\s(def|if|with|else|try|except:) /
    $f_exotic     = /exec\(|b64decode|bytes\(/
    $f_for        = /for [a-z] in/
    $f_join       = ".join("
    $f_requests   = /(from|import) requests/
    $f_requests2  = "requests."
    $f_subprocess = /subprocess.(Popen|run)/

  condition:
    filesize < 10MB and ($import in (1..1024) or any of ($f*))
}

rule js_eval: medium {
  meta:
    description = "evaluate code dynamically using eval()"

  strings:
    $val       = /eval\([\.\+ _a-zA-Z\"\'\(\,\)]{1,32}/ fullword
    $val2      = "eval(this.toString());"
    $not_empty = "eval()"

  condition:
    eval_probably_js and filesize < 1MB and any of ($val*) and none of ($not*)
}

rule js_eval_fx_str: high {
  meta:
    description = "evaluate processed string using eval()"

  strings:
    $val = /eval\(\w{0,16}\([\"\'].{0,16}/

  condition:
    eval_probably_js and filesize < 1MB and any of ($val*)
}

rule js_eval_fx_str_multiple: critical {
  meta:
    description = "multiple evaluations of processed string using eval()"

  strings:
    $val = /eval\(\w{0,16}\([\"\'].{0,16}/

  condition:
    eval_probably_js and filesize < 1MB and #val > 1
}

rule js_eval_response: critical {
  meta:
    description = "executes code directly from HTTP response"

  strings:
    $val = /eval\(\w{0,16}\.responseText\)/

  condition:
    eval_probably_js and filesize < 1MB and any of ($val*)
}

rule js_eval_near_enough_fromChar: high {
  meta:
    description = "Likely executes encrypted content"

  strings:
    $exec    = /[\s\{]eval\(/
    $decrypt = "String.fromCharCode"

  condition:
    eval_probably_js and filesize < 5MB and all of them and math.abs(@exec - @decrypt) > 384
}

rule js_eval_obfuscated_fromChar: critical {
  meta:
    description = "Likely executes encrypted content"

  strings:
    $exec = /[\s\{]eval\(/
    $ref  = /fromCharCode\(\w{0,16}\s{0,2}[\-\+\*\^]{0,2}\w{0,16}/

  condition:
    eval_probably_js and filesize < 5MB and all of them and math.abs(@exec - @ref) > 384
}

rule js_anonymous_function: medium {
  meta:
    description = "evaluates code using an anonymous function"

  strings:
    $func = /\n\s{0,8}\(function\s{0,8}\(\)\s{0,8}\{/
    $run  = /\n\s{0,8}\}\)\(\);/

  condition:
    eval_probably_js and filesize < 5MB and all of them and (@run - @func) > 384
}

rule python_exec: medium {
  meta:
    description = "evaluate code dynamically using exec()"

  strings:
    $f_import = "import" fullword
    $f_join   = ".join("
    $f_chr    = "chr("
    $f_int    = "int("
    $f_for    = /for [a-z] in /
    $val      = /exec\([\w\ \"\'\.\(\)\[\]]{1,64}/ fullword
    $empty    = "exec()"

  condition:
    eval_probably_python and filesize < 1MB and any of ($f*) and $val and not $empty
}

rule python_exec_near_enough_chr: high {
  meta:
    description = "Likely executes encoded character content"

  strings:
    $exec = "exec("
    $chr  = "chr("

  condition:
    eval_probably_python and all of them and math.abs(@chr - @exec) < 768
}

rule python_exec_near_enough_fernet: high {
  meta:
    description = "Likely executes Fernet encrypted content"

  strings:
    $exec   = "exec("
    $fernet = "Fernet("

  condition:
    eval_probably_python and all of them and math.abs(@exec - @fernet) < 768
}

rule python_exec_near_enough_decrypt: high {
  meta:
    description = "Likely executes encrypted content"

  strings:
    $exec    = /\bexec\(/
    $decrypt = "decrypt("

  condition:
    eval_probably_python and all of them and math.abs(@exec - @decrypt) < 768
}

rule python_exec_chr: critical {
  meta:
    description = "Executes encoded character content"

  strings:
    $exec = /exec\(.{0,16}chr\(.{0,16}\[\d[\d\, ]{0,64}/

  condition:
    eval_probably_python and filesize < 512KB and all of them
}

rule python_exec_bytes: critical {
  meta:
    description = "Executes a transformed bytestream"

  strings:
    $exec = /exec\([\w\.\(]{0,16}\(b['"].{8,16}/

  condition:
    eval_probably_python and filesize < 512KB and all of them
}

rule python_exec_complex: high {
  meta:
    description = "Executes code from a complex expression"

  strings:
    $exec           = /exec\([\w\. =]{1,32}\(.{0,8192}\)\)/ fullword
    $not_javascript = "function("
    $not_pyparser   = "exec(compile(open(self.parsedef).read(), self.parsedef, 'exec'))"
    $not_versioneer = "exec(VERSIONEER.decode(), globals())"

  condition:
    eval_probably_python and filesize < 512KB and $exec and none of ($not*)
}

rule python_exec_fernet: critical {
  meta:
    description = "Executes Fernet encrypted content"

  strings:
    $exec = /exec\(.{0,16}Fernet\(.{0,64}/

  condition:
    eval_probably_python and filesize < 512KB and all of them
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
