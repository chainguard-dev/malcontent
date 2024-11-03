rule unsigned_bitwise_math: medium {
  meta:
    description = "uses unsigned bitwise math"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "javascript"

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
    filetypes   = "javascript"

  strings:
    $function = "function("
    $charAt   = /charAt\([a-zA-Z]/

    $left  = /[a-z]\>\>\>\d{1,3}/
    $right = /[a-z]\>\>\>\d{1,3}/

  condition:
    filesize < 5MB and $function and $charAt and (#left > 50 or #right > 50)
}
