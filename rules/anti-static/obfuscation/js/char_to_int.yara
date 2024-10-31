rule js_char_code_at_substitution: high {
  meta:
    description = "converts strings into integers and contains a substitution map"
    filetypes   = "javascript"

  strings:
    $charCodeAt = "charCodeAt" fullword
    $index      = "fghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

  condition:
    filesize < 256KB and all of them
}
