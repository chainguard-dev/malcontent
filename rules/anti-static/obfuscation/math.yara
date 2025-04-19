rule js_long_math: high {
  meta:
    description = "performs multiple rounds of long integer math"

  strings:
    $f_function = "function"
    $f_return   = "return"
    $f_local    = "local"
    $f_end      = "end" fullword

    $d = /\d{6,14}[\+\-]\d{6,14}/ fullword

  condition:
    3 of ($f*) and #d > 64
}

rule js_long_dumb_math: critical {
  meta:
    description = "performs multiple rounds of long dumb integer math"

  strings:
    $f_function = "function"
    $f_return   = "return"
    $f_local    = "local"
    $f_end      = "end" fullword

    $d = /[-\+]\([-\+]\d{6,14}[-\+]\([-\+]\d{6,14}\)\)/

  condition:
    2 of ($f*) and #d > 32
}
