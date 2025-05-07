import "math"

private rule obfs_probably_js {
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

rule character_obfuscation: medium {
  meta:
    description = "obfuscated javascript that relies on character manipulation"
    filetypes   = "javascript"

  strings:
    $a_char         = "charCodeAt"
    $a_charAt       = "charAt"
    $a_toString     = "toString"
    $a_length       = "length"
    $a_fromCharCode = "fromCharCode"
    $a_shift        = "shift"
    $a_push         = "push"

    $const    = "const "
    $function = "function("
    $return   = "{return"

  condition:
    obfs_probably_js and filesize < 4MB and all of them
}

rule js_char_code_at_substitution: low {
  meta:
    description = "converts integers into strings and contains a substitution map"
    filetypes   = "javascript"

  strings:
    $charCodeAt = "charCodeAt" fullword
    $index      = "fghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

  condition:
    obfs_probably_js and filesize < 256KB and all of them
}

rule child_process: medium {
  meta:
    description = "obfuscated javascript that calls external programs"

  strings:
    $f_const         = "const" fullword
    $f_return        = "return" fullword
    $f_var           = "var" fullword
    $o_child_process = "child_process"
    $o_decode        = "decode("
    $o_tostring      = "toString("
    $o_from          = ".from("
    $wtf_hex         = /\w{4,16}\<\-0x\d{2,4}/

  condition:
    obfs_probably_js and filesize < 1MB and all of them and math.entropy(1, filesize) >= 6
}

rule ebe: medium {
  meta:
    description = "highly obfuscated javascript (eBe)"
    filetypes   = "javascript"

  strings:
    $function   = "function("
    $charCodeAt = "charCodeAt"

    $ref = /eBe\([-]?\d{1,3}\)/

  condition:
    obfs_probably_js and filesize < 5MB and $function and $charCodeAt and #ref > 10
}

rule ebe_generic: low {
  meta:
    description = "highly obfuscated javascript"
    filetypes   = "javascript"

  strings:
    $function   = "function("
    $charCodeAt = "charCodeAt"

    $ref  = /\w\[\w{1,3}\(\d{1,3}\)\]=\w{1,3}\(\d{1,3}\),e\[\w{1,3}\(\d{1,3}\)\]/
    $ref2 = /\w\[\w{1,3}\(\d{1,3}\)\]\&\w{1,3}\(\d{1,3}\)\),\w\[\w{1,3}\(\d{1,3}\)\]/
    $ref3 = /\>\w{1,3}\(\d{1,3}\)\);\w\[\w{1,3}\(\d{1,3}\)\]\=/

  condition:
    obfs_probably_js and filesize < 5MB and #function > 0 and $charCodeAt and (#ref > 5 or #ref2 > 5 or #ref3 > 5)
}

rule exec_console_log: critical {
  meta:
    description = "evaluates the return of console.log()"

  strings:
    $ref = ".exec(console.log("

  condition:
    any of them
}

rule js_const_func_obfuscation: medium {
  meta:
    description = "javascript obfuscation (excessive const functions)"

  strings:
    $const    = "const "
    $function = "function("
    $return   = "{return"

  condition:
    obfs_probably_js and filesize < 256KB and #const > 32 and #function > 48 and #return > 64
}

rule js_hex_eval_obfuscation: critical {
  meta:
    description = "javascript eval obfuscation (hex)"

  strings:
    $return = /\(eval, _{0,4}0x[\w]{0,32}[\(\[]/

  condition:
    obfs_probably_js and filesize < 128KB and any of them
}

rule js_hex_obfuscation: medium {
  meta:
    description = "javascript function obfuscation (hex)"

  strings:
    $return = /return _{0,4}0x[\w]{0,32}[\(\w]{0,32}/
    $const  = /const _{0,4}0x[\w]{0,32}\s*=[\w]{0,32}/

  condition:
    obfs_probably_js and filesize < 1MB and any of them
}

rule high_entropy: low {
  meta:
    description = "high entropy javascript (>6)"

  condition:
    obfs_probably_js and math.entropy(1, filesize) >= 6
}

rule very_high_entropy: medium {
  meta:
    description = "very high entropy javascript (>7)"

  condition:
    obfs_probably_js and math.entropy(1, filesize) >= 7
}

rule charCodeAtIncrement: medium {
  meta:
    description = "converts incremented numbers into characters"
    filetypes   = "javascript"

  strings:
    $function  = "function("
    $increment = /charCodeAt\(\+\+\w{0,4}\)/

  condition:
    obfs_probably_js and filesize < 4MB and $function and #increment > 1
}

rule js_many_parseInt: medium {
  meta:
    description = "javascript obfuscation (integer parsing)"
    filetypes   = "javascript"

  strings:
    $const    = "const "
    $function = "function("
    $return   = "{return"
    $parseInt = "parseInt"

  condition:
    obfs_probably_js and filesize < 256KB and #const > 16 and #function > 32 and #parseInt > 8 and #return > 32
}

rule over_powered_arrays: high {
  meta:
    description = "uses many powered array elements (>25)"
    filetypes   = "javascript"

  strings:
    $function    = /function\(\w,/
    $charAt      = /charAt\([a-zA-Z]/
    $power_array = /\w\[\d{1,4}\]\^\w\[\d{1,4}\]/

  condition:
    obfs_probably_js and filesize < 5MB and $function and $charAt and #power_array > 25
}

rule string_prototype_function: high {
  meta:
    description = "obfuscates function calls via string prototypes"

  strings:
    $ref  = /String\["prototype"\].{1,32} = function\(\) \{ eval\(this\.toString\(\)\)\;/
    $ref2 = /String\["prototype"\]\[".{4,64}"\] = function\(\w{1,2}, \w{1,2}\) \{/

  condition:
    any of them
}

rule unicode_prototype: critical {
  meta:
    description = "sets obfuscated Array.prototype attribute"

  strings:
    $ref = /Array\.prototype\.\\[\w\\]{2,256}\s{0,2}=.{0,64}/

  condition:
    obfs_probably_js and any of them
}

rule var_filler: medium {
  meta:
    description = "header is filled with excessive variable declarations"

  strings:
    $ref = /[a-z]{2,8}\d{1,5} = "[a-z]{2,8}\d{1,5}"/ fullword

  condition:
    #ref > 25
}

rule large_random_variables: high {
  meta:
    description = "contains large random variable names"

  strings:
    $ref = /var [a-zA-Z_]{32,256} = '.{4}/ fullword

  condition:
    obfs_probably_js and #ref > 1
}

rule many_complex_var: medium {
  meta:
    description = "defines multiple complex variables"

  strings:
    $ref = /var [a-zA-Z_]{1,256} = \(/

  condition:
    obfs_probably_js and #ref > 64
}

rule many_complex_var_high: high {
  meta:
    description = "excessive complex variable declarations"

  strings:
    $ref = /var [a-zA-Z_]{1,256} = \(.{1,64}/

  condition:
    obfs_probably_js and #ref > 400
}

rule many_static_map_lookups: medium {
  meta:
    description = "contains large number of static map lookups"

  strings:
    $ref = /\[[\"\'][a-z]{1,32}[\"\']\]/

  condition:
    obfs_probably_js and #ref > 128
}

rule obfuscated_map_to_array_conversions: high {
  meta:
    description = "obfuscated map to array conversions"

  strings:
    $ref = /\[[\"\'a-z]{1,32}\]\s{0,2}\+\s{0,2}\[\]\)\[\d{1,4}\]/

  condition:
    obfs_probably_js and #ref > 32
}

rule large_obfuscated_array: medium {
  meta:
    description = "contains large obfuscated arrays"

  strings:
    $ref  = /[a-z]{32,256}=\[\]/ fullword
    $ref2 = /[a-z]{1,256}\[\'\w{32,2048}\'\]/ fullword

  condition:
    obfs_probably_js and all of them
}

rule high_entropy_charAt: medium {
  meta:
    description = "high entropy javascript (>5.37) that uses charAt/substr/join loops"

  strings:
    $ = "charAt("
    $ = "substr("
    $ = "join("
    $ = "function("
    $ = "for("

  condition:
    obfs_probably_js and math.entropy(1, filesize) >= 5.37 and all of them
}
