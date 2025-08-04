import "math"

rule decode_url_component_char_code: medium {
  meta:
    description = "decodes obfuscated URL components"
    filetypes   = "js,ts"

  strings:
    $ref          = "decodeURIComponent"
    $charCodeAt   = "charCodeAt"
    $fromCharCode = "fromCharCode"

  condition:
    filesize < 1MB and all of them and (math.abs(@charCodeAt - @ref) <= 128) or (math.abs(@fromCharCode - @ref) <= 128)
}
