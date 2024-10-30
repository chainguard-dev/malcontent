rule js_char_code_at: medium {
  meta:
    description = "converts strings into integers"
    filetypes   = "javascript"

  strings:
    $charCodeAt = "fromCharCode" fullword

  condition:
    filesize < 16KB and any of them
}
