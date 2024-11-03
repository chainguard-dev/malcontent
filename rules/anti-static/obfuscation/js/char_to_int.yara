rule js_char_code_at_substitution: high {
  meta:
    description = "converts integers into strings and contains a substitution map"
    filetypes   = "javascript"

  strings:
    $charCodeAt = "charCodeAt" fullword
    $index      = "fghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

  condition:
    filesize < 256KB and all of them
}

rule chartBitwise: high {
  meta:
    description = "converts manipulated numbers into characters"
    filetypes   = "javascript"

  strings:
    $function    = "function("
    $c_left      = /charAt\([a-z]\>\>\>\d.{0,8}/
    $c_remainder = /charAt\(\w%\w.{0,8}/

  condition:
    filesize < 5MB and $function and any of ($c*)
}
