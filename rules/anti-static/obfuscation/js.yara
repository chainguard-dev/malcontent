import "math"

rule js_var_misdirection: medium {
  meta:
    description = "multiple layers of variable misdirection"
    filetypes   = "js,ts"

  strings:
    $short_mix_high = /var [a-z]{0,2}[A-Z]{1,2}[a-z]\w{1,2}\s{0,2}=\s{0,2}\w{0,2}[A-Z]\w{1,2}[\;\(\[]/
    $empty          = /var [a-z]{1,3}[A-Z][a-z]{0,2}\s{0,2}=\s{0,2}"";/
    $short_mix_low  = /var [a-z][A-Z]{1,6}\w{1,2}\s{0,2}=\s{0,2}\w{0,2}[A-Z]\w{1,2}[\;\(\[]/
    $short_low      = /var [a-z]{1,3}\s{0,2}=\s{0,2}\w{0,2}[A-Z]\w{1,2}[\;\(\[]/

  condition:
    filesize < 4MB and 3 of them
}

rule character_obfuscation: medium {
  meta:
    description = "obfuscated javascript that relies on character manipulation"
    filetypes   = "js,ts"

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
    filesize < 4MB and all of them
}

rule js_char_code_at_substitution: high {
  meta:
    description = "converts integers into strings and contains a substitution map"
    filetypes   = "js,ts"

  strings:
    $charCodeAt = "charCodeAt" fullword
    $index      = "fghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

  condition:
    filesize < 256KB and all of them
}

rule child_process: high {
  meta:
    description = "obfuscated javascript that calls external programs"
    filetypes   = "js,ts"

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
    filesize < 1MB and all of them and math.entropy(1, filesize) >= 6
}

rule ebe: high {
  meta:
    description = "highly obfuscated javascript (eBe)"
    filetypes   = "js,ts"

  strings:
    $function   = "function("
    $charCodeAt = "charCodeAt"

    $ref = /eBe\([-]?\d{1,3}\)/

  condition:
    filesize < 5MB and $function and $charCodeAt and #ref > 10
}

rule ebe_generic: high {
  meta:
    description = "highly obfuscated javascript"
    filetypes   = "js,ts"

  strings:
    $function   = "function("
    $charCodeAt = "charCodeAt"

    $ref  = /\w\[\w{1,3}\(\d{1,3}\)\]=\w{1,3}\(\d{1,3}\),e\[\w{1,3}\(\d{1,3}\)\]/
    $ref2 = /\w\[\w{1,3}\(\d{1,3}\)\]\&\w{1,3}\(\d{1,3}\)\),\w\[\w{1,3}\(\d{1,3}\)\]/
    $ref3 = /\>\w{1,3}\(\d{1,3}\)\);\w\[\w{1,3}\(\d{1,3}\)\]\=/

  condition:
    filesize < 5MB and #function > 0 and $charCodeAt and (#ref > 5 or #ref2 > 5 or #ref3 > 5)
}

rule exec_console_log: critical {
  meta:
    description = "evaluates the return of console.log()"
    filetypes   = "js,ts"

  strings:
    $ref = ".exec(console.log("

  condition:
    any of them
}

rule js_const_func_obfuscation: medium {
  meta:
    description = "javascript obfuscation (excessive const functions)"
    filetypes   = "js,ts"

  strings:
    $const    = "const "
    $function = "function("
    $return   = "{return"

  condition:
    filesize < 256KB and #const > 32 and #function > 48 and #return > 64
}

rule js_hex_eval_obfuscation: high {
  meta:
    description = "javascript eval obfuscation (hex)"
    filetypes   = "js,ts"

  strings:
    $return = /\(eval, _{0,4}0x[\w]{0,32}[\(\[]/

  condition:
    filesize < 128KB and any of them
}

rule js_hex_obfuscation: high {
  meta:
    description = "javascript function obfuscation (hex)"
    filetypes   = "js,ts"

  strings:
    $return = /return _{0,4}0x[\w]{0,32}[\(\w]{0,32}/
    $const  = /const _{0,4}0x[\w]{0,32}\s*=[\w]{0,32}/

  condition:
    filesize < 1MB and any of them
}

rule high_entropy: medium {
  meta:
    description = "high entropy javascript (>6)"
    filetypes   = "js,ts"

  condition:
    math.entropy(1, filesize) >= 6
}

rule very_high_entropy: high {
  meta:
    description = "very high entropy javascript (>7)"
    filetypes   = "js,ts"

  condition:
    math.entropy(1, filesize) >= 7
}

rule charCodeAtIncrement: medium {
  meta:
    description = "converts incremented numbers into characters"
    filetypes   = "js,ts"

  strings:
    $function  = "function("
    $increment = /charCodeAt\(\+\+\w{0,4}\)/

  condition:
    filesize < 4MB and $function and #increment > 1
}

rule js_many_parseInt: high {
  meta:
    description = "javascript obfuscation (integer parsing)"
    filetypes   = "js,ts"

  strings:
    $const    = "const "
    $function = "function("
    $return   = "{return"
    $parseInt = "parseInt"

  condition:
    filesize < 256KB and #const > 16 and #function > 32 and #parseInt > 8 and #return > 32
}

rule over_powered_arrays: high {
  meta:
    description = "uses many powered array elements (>25)"
    filetypes   = "js,ts"

  strings:
    $function    = /function\(\w,/
    $charAt      = /charAt\([a-zA-Z]/
    $power_array = /\w\[\d{1,4}\]\^\w\[\d{1,4}\]/

  condition:
    filesize < 5MB and $function and $charAt and #power_array > 25
}

rule string_prototype_function: high {
  meta:
    description = "obfuscates function calls via string prototypes"
    filetypes   = "js,ts"

  strings:
    $ref  = /String\["prototype"\].{1,32} = function\(\) \{ eval\(this\.toString\(\)\)\;/
    $ref2 = /String\["prototype"\]\[".{4,64}"\] = function\(\w{1,2}, \w{1,2}\) \{/

  condition:
    any of them
}

rule unicode_prototype: critical {
  meta:
    description = "sets obfuscated Array.prototype attribute"
    filetypes   = "js,ts"

  strings:
    $ref = /Array\.prototype\.\\[\w\\]{2,256}\s{0,2}=.{0,64}/

  condition:
    any of them
}

rule var_filler: high {
  meta:
    description = "header is filled with excessive variable declarations"
    filetypes   = "js,ts"

  strings:
    $ref = /[a-z]{2,8}\d{1,5} = "[a-z]{2,8}\d{1,5}"/ fullword

  condition:
    #ref > 25
}

rule large_random_variables: high {
  meta:
    description = "contains large random variable names"
    filetypes   = "js,ts"

  strings:
    $ref = /var [a-zA-Z_]{32,256} = '.{4}/ fullword

  condition:
    #ref > 1
}

rule many_complex_var: medium {
  meta:
    description = "defines multiple complex variables"
    filetypes   = "js,ts"

  strings:
    $ref = /var [a-zA-Z_]{1,256} = \(/

  condition:
    #ref > 64
}

rule many_complex_var_high: high {
  meta:
    description = "excessive complex variable declarations"
    filetypes   = "js,ts"

  strings:
    $ref = /var [a-zA-Z_]{1,256} = \(.{1,64}/

  condition:
    #ref > 400
}

rule many_static_map_lookups: medium {
  meta:
    description = "contains large number of static map lookups"
    filetypes   = "js,ts"

  strings:
    $ref = /\[[\"\'][a-z]{1,32}[\"\']\]/

  condition:
    #ref > 128
}

rule obfuscated_map_to_array_conversions: high {
  meta:
    description = "obfuscated map to array conversions"
    filetypes   = "js,ts"

  strings:
    $ref = /\[[\"\'a-z]{1,32}\]\s{0,2}\+\s{0,2}\[\]\)\[\d{1,4}\]/

  condition:
    #ref > 32
}

rule large_obfuscated_array: high {
  meta:
    description = "contains large obfuscated arrays"
    filetypes   = "js,ts"

  strings:
    $ref  = /[a-z]{32,256}=\[\]/ fullword
    $ref2 = /[a-z]{1,256}\[\'\w{32,2048}\'\]/ fullword

  condition:
    all of them
}

rule high_entropy_charAt: medium {
  meta:
    description = "high entropy javascript (>5.37) that uses charAt/substr/join loops"
    filetypes   = "js,ts"

  strings:
    $           = "charAt("
    $           = "substr("
    $           = "join("
    $s_function = /function\s{0,2}\(/
    $s_for      = /for\s{0,2}\(/

  condition:
    math.entropy(1, filesize) >= 5.37 and all of them
}

rule charAt_long_string: medium {
  meta:
    description = "charAt/substr operations with long strings"
    filetypes   = "js,ts"

  strings:
    $charAt = "charAt("
    $substr = "substr("
    $join   = "join("
    $func   = "function"
    $for    = "for"

    $long1 = /["'][a-zA-Z0-9]{32,}["']/
    $long2 = /["']\w{50,}["']/

  condition:
    2 of ($charAt, $substr, $join) and
    $func and $for and
    any of ($long*)
}

rule charAt_multiple_suspicious: medium {
  meta:
    description = "Multiple suspicious string patterns with charAt operations"
    filetypes   = "js,ts"

  strings:
    $charAt = "charAt("
    $substr = "substr("
    $join   = "join("

    $susp1 = /["'][a-zA-Z0-9]{32,}["']/
    $susp2 = /["'][!@#$%^&*(){}\[\]]{8,}["']/
    $susp3 = /["'][0-9a-fA-F]{32,}["']/
    $susp4 = /["'][a-zA-Z0-9+\/=]{50,}["']/

  condition:
    2 of ($charAt, $substr, $join) and
    #susp1 + #susp2 + #susp3 + #susp4 > 3
}

rule obfuscated_require: high {
  meta:
    description = "sets variable to the 'require' keyword"
    filetypes   = "js,ts"

  strings:
    $ = /global\[\"\w{1,16}\"\]\s{0,2}=\s{0,2}require;/
    $ = /var \w{1,16}\s{0,2}=\s{0,2}require;/

  condition:
    math.entropy(1, filesize) >= 5.37 and all of them
}
