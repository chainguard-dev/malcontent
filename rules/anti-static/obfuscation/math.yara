rule js_long_math: high {
  meta:
    description = "performs multiple rounds of long integer math"
    filetypes   = "js,ts"

  strings:
    $d = /\d{6,14}[\+\-]\d{6,14}/ fullword

  condition:
    #d > 64
}

rule js_long_dumb_math: critical {
  meta:
    description = "performs multiple rounds of long dumb integer math"
    filetypes   = "js,ts"

  strings:
    $d = /[-\+]\([-\+]\d{6,14}[-\+]\([-\+]\d{6,14}\)\)/

  condition:
    #d > 32
}

rule js_junk_math: medium {
  meta:
    description   = "suspicious junk math operations with charAt"
    filetypes     = "js,ts"
    severity_note = "1-2 patterns = medium, 3+ patterns = high"

  strings:
    $charAt = "charAt"

    $m_subtract  = /\s\w{1,16}\s?=\s?\d{0,8}\s?-\s?\d{2,8};/
    $m_var_int   = /var\s+\w{1,16}\s?=\s?\d{3,16};/
    $m_paren_add = /\(\w{1,8}\s?\+\s?\d{2,16}\)/
    $m_paren_rem = /\(\w{1,8}\s?%\s?\d{4,16}\)/
    $m_tiny_rem  = /\w{1,2}\s?=\s?\(\w\s?\+\s?\w\)\s?%\s?\d{4,16};/

  condition:
    $charAt and any of ($m*)
}

rule sketchy_math_conversions: medium {
  meta:
    description = "complex math with parseInt or fromCharCode conversions"
    filetypes   = "js,ts"

  strings:
    $f_parseInt     = "parseInt"
    $f_fromCharCode = "fromCharCode"

    $math1 = /\d{2,16}[\+\-\*\/]\w{1,8}/
    $math2 = /\w{1,8}[\+\-\*\/]\d{2,16}/

    $xor1 = /\d{2,16}\^\w{1,8}/
    $xor2 = /\w{1,8}\^\d{2,16}/

    $complex_math = /[\(\[][\w\d\s\+\-\*\/\^]{10,50}[\)\]]/

  condition:
    filesize < 1MB and
    ($f_parseInt or $f_fromCharCode) and
    (
      (#math1 + #math2 > 5) or
      (#xor1 + #xor2 > 2) or
      #complex_math > 3
    )
}
