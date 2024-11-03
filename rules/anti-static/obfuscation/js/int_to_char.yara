rule js_char_code_at: medium {
  meta:
    description = "converts strings into integers"
    filetypes   = "javascript"

  strings:
    $charCodeAt = "fromCharCode" fullword

  condition:
    filesize < 16KB and any of them
}

rule charCodeAtIncrement: high {
  meta:
    description = "converts incremented numbers into characters"
    filetypes   = "javascript"

  strings:
    $function  = "function("
    $increment = /charCodeAt\(\+\+\w{0,4}\)/

  condition:
    filesize < 4MB and $function and #increment > 1
}
