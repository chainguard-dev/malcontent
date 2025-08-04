import "math"

rule large_bitwise_math: medium {
  meta:
    description = "large amounts of bitwise math"

  strings:
    $x = /\-{0,1}\d{1,8} \<\< \-{0,1}\d{1,8}/

  condition:
    filesize < 256KB and #x > 16
}

rule excessive_bitwise_math: high {
  meta:
    description = "excessive use of bitwise math (>64 ops)"

  strings:
    $x                  = /\-{0,1}[\da-z]{1,8} \<\< \-{0,1}\d{1,8}/
    $not_Sodium         = "Sodium_Core"
    $not_SHA512         = "SHA512"
    $not_SHA256         = "SHA256"
    $not_MD4            = "MD4"
    $not_algbase        = "algbase" fullword
    $not_jslint         = "jslint bitwise"
    $not_include        = "#define "
    $not_bitwise        = "bitwise" fullword
    $not_bitmasks       = "bitmasks" fullword
    $not_ckbcomp        = "ckbcomp" fullword
    $not_bit_test       = "bits_test" fullword
    $not_testing        = "*testing.T"
    $not_effective_bits = "effective bits"
    $not_bit_offsets    = "bit offsets"
    $not_uuid           = "uuid" fullword
    $not_webpack        = "webpack-api-runtime.js" fullword

  condition:
    filesize < 192KB and #x > 64 and none of ($not*)
}

rule bitwise_math: low {
  meta:
    description = "uses bitwise math"
    filetypes   = "py"

  strings:
    $x = /\-{0,1}[\da-z]{1,8} \<\< \-{0,1}\d{1,8}/
    $y = /\-{0,1}[\da-z]{1,8} \>\> \-{0,1}\d{1,8}/

  condition:
    filesize < 192KB and any of them
}

rule bidirectional_bitwise_math: medium {
  meta:
    description = "uses bitwise math in both directions"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "py"

  strings:
    $x = /\-{0,1}[\da-z]{1,8} \<\< \-{0,1}\d{1,8}/
    $y = /\-{0,1}[\da-z]{1,8} \>\> \-{0,1}\d{1,8}/

  condition:
    filesize < 192KB and all of them
}

rule bitwise_python_string: medium {
  meta:
    description = "creates string using bitwise math"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "py"

  strings:
    $ref = /"".join\(chr\(\w{1,4} >> \w{1,3}\) for \w{1,16} in \w{1,16}/

  condition:
    filesize < 65535 and $ref
}

rule bitwise_python_string_exec_eval: high {
  meta:
    description = "creates and evaluates string using bitwise math"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "py"

  strings:
    $ref  = /"".join\(chr\(\w{1,4} >> \w{1,3}\) for \w{1,16} in \w{1,16}/
    $exec = "exec("
    $eval = "eval("

  condition:
    filesize < 65535 and $ref and any of ($e*)
}

rule bitwise_python_string_exec_eval_nearby: critical {
  meta:
    description = "creates and executes string using bitwise math"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "py"

  strings:
    $ref  = /"".join\(chr\(\w{1,4} >> \w{1,3}\) for \w{1,16} in \w{1,16}/
    $exec = "exec("
    $eval = "eval("

  condition:
    filesize < 65535 and $ref and any of ($e*) and (math.abs(@ref - @exec) <= 64 or (math.abs(@ref - @eval) <= 64))
}

rule unsigned_bitwise_math: medium {
  meta:
    description = "uses unsigned bitwise math"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "js,ts"

  strings:
    $function = "function("
    $charAt   = /charAt\([a-zA-Z]/

    $left  = /[a-z]\>\>\>\d{1,3}/
    $right = /[a-z]\>\>\>\d{1,3}/

  condition:
    filesize < 5MB and $function and $charAt and (#left > 5 or #right > 5)
}

rule unsigned_bitwise_math_excess: high {
  meta:
    description = "uses an excessive amount of unsigned bitwise math"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "js,ts"

  strings:
    $function = "function("
    $charAt   = /charAt\([a-zA-Z]/

    $left  = /[a-z]\>\>\>\d{1,3}/
    $right = /[a-z]\>\>\>\d{1,3}/

    $not_elastic1 = "/*! Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one or more contributor license agreements."
    $not_elastic2 = "* Licensed under the Elastic License 2.0; you may not use this file except in compliance with the Elastic License 2.0. */"
    $not_webpack  = "webpack-api-runtime.js" fullword
    $not_wso2is   = "(self.webpackChunk_wso2is_console=self.webpackChunk_wso2is_console||[])"

  condition:
    filesize < 5MB and $function and $charAt and (#left > 50 or #right > 50) and none of ($not*)
}

rule charAtBitwise: high {
  meta:
    description = "converts manipulated numbers into characters"
    filetypes   = "js,ts"

  strings:
    $function    = "function("
    $c_left      = /charAt\([a-z]\>\>\>\d.{0,8}/
    $c_remainder = /charAt\(\w%\w.{0,8}/

  condition:
    filesize < 5MB and $function and any of ($c*)
}

rule bidirectional_bitwise_math_php: high {
  meta:
    description = "uses bitwise math in both directions"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "php"

  strings:
    $php = "<?php"
    $x   = /\-{0,1}[\da-z]{1,8} \<\< \-{0,1}\d{1,8}/
    $y   = /\-{0,1}[\da-z]{1,8} \>\> \-{0,1}\d{1,8}/

  condition:
    filesize < 192KB and all of them
}

rule bitwise_obfuscation: high {
  meta:
    description = "uses bitwise math to obfuscate code"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "php"

  strings:
    $php       = "<?php"
    $bit1      = /\-{0,1}[\da-z]{1,8} \<\< \-{0,1}\d{1,8}/
    $bit2      = /\-{0,1}[\da-z]{1,8} \>\> \-{0,1}\d{1,8}/
    $f_implode = "implode("
    $f_charAt  = "charAt("
    $f_substr  = "substr("
    $f_ord     = "ord("

  condition:
    filesize < 192KB and $php and any of ($bit*) and 3 of ($f*)
}
