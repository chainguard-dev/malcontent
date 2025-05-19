private rule math_probably_js {
  strings:
    $f_function = "function"
    $f_return   = "return"
    $f_local    = "local"
    $f_var      = "var" fullword
    $f_global   = "global["
    $f_end      = "end" fullword

  condition:
    filesize < 5MB and 3 of ($f*)
}

rule js_long_math: high {
  meta:
    description = "performs multiple rounds of long integer math"
    filetypes   = "application/javascript"

  strings:
    $d = /\d{6,14}[\+\-]\d{6,14}/ fullword

  condition:
    math_probably_js and #d > 64
}

rule js_long_dumb_math: critical {
  meta:
    description = "performs multiple rounds of long dumb integer math"
    filetypes   = "application/javascript"

  strings:
    $d = /[-\+]\([-\+]\d{6,14}[-\+]\([-\+]\d{6,14}\)\)/

  condition:
    math_probably_js and #d > 32
}

rule js_junk_math: medium {
  meta:
    description = "suspicious junk math"

  strings:
    $charAt                     = "charAt"
    $m_subtract_var             = /\s\w{1,16}\s{0,2}=\s{0,2}\d{0,8}\s{0,2}-\s{0,2}\d{1,8};/
    $m_var_int                  = /var\s{1,16}\w{0,16}\s{0,2}=\s{0,2}\d{3,16};/
    $m_paren_add                = /\(\w{0,8}\s{0,2}\+\s{0,2}\d{1,16}\)/
    $m_paren_long_remainder     = /\(\w{0,8}\s{0,2}%\s{0,2}\d{4,16}\)/
    $m_tiny_vars_long_remainder = /\w{0,2}\s{0,2}=\s{0,2}\(\w + \w\) % \d{4,16};/

  condition:
    math_probably_js and $charAt and 2 of ($m*)
}

rule js_junk_math_high: high {
  meta:
    description = "multiple examples of suspicious junk math"

  strings:
    $charAt                     = "charAt"
    $m_subtract_var             = /\s\w{1,16}\s{0,2}=\s{0,2}\d{0,8}\s{0,2}-\s{0,2}\d{2,8};/
    $m_var_int                  = /var\s{1,16}\w{0,16}\s{0,2}=\s{0,2}\d{3,16};/
    $m_paren_add                = /\(\w{0,8}\s{0,2}\+\s{0,2}\d{2,16}\)/
    $m_paren_long_remainder     = /\(\w{0,8}\s{0,2}%\s{0,2}\d{4,16}\)/
    $m_tiny_vars_long_remainder = /\w{0,2}\s{0,2}=\s{0,2}\(\w + \w\) % \d{4,16};/

  condition:
    math_probably_js and $charAt and 3 of ($m*)
}
