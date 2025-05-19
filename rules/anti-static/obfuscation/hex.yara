rule excessive_hex_refs: medium {
  meta:
    description = "many references to hexadecimal values"

  strings:
    $x = /0x[\dabcdefABCDEF]{2,8}/
    $y = /\\x[\dabcdefABCDEF]{2,8}/

  condition:
    filesize < 1MB and (#x > 64 or #y > 256)
}

rule hex_parse: medium {
  meta:
    description = "converts hex data to ASCII"
    filetypes   = "py"

  strings:
    $node   = /Buffer\.from\(\w{0,16}, {0,2}'hex'\)/
    $node2  = /toString\(['"]hex['"]\);/
    $python = /unhexlify/

  condition:
    any of them
}

rule hex_convert_from_base64: medium {
  meta:
    description = "converts base64 hex data to ASCII"
    filetypes   = "py"

  strings:
    $lang_node   = /Buffer\.from\(\w{0,16}, {0,2}'hex'\)/
    $lang_python = /\.unhexlify\(/
    $b_base64    = "base64"
    $b_b64decode = "b64decode"

  condition:
    filesize < 32KB and any of ($lang*) and any of ($b*)
}

rule hex_parse_base64_high: high {
  meta:
    description = "converts base64 hex data to ASCII"
    filetypes   = "py"

  strings:
    $lang_node         = /Buffer\.from\(\w{0,16}, {0,2}'hex'\)/
    $lang_python       = /\.unhexlify\(/
    $b_base64          = "base64"
    $b_b64decode       = "b64decode"
    $not_sha256        = "sha256" fullword
    $not_sha512        = "sha512" fullword
    $not_algorithms    = "algorithms" fullword
    $not_python_base64 = "return binascii.unhexlify(s)"

  condition:
    filesize < 32KB and any of ($lang*) and any of ($b*) and none of ($not*)
}

rule mega_string: high {
  meta:
    description = "python script decodes large hexadecimal string"
    filetypes   = "py"

  strings:
    $unhexlify            = "unhexlify"
    $hex_multiline_single = /= {0,2}'''[\/\da-fA-F]{1024}/
    $hex_multiline_double = /= {0,2}"""[\/\da-fA-F]{1024}/
    $hex_line_single      = /= '[\/\da-fA-F]{1024}/
    $hex_line_double      = /= "[\/\da-fA-F]{1024}/

  condition:
    filesize < 5MB and $unhexlify and any of ($hex*)

}

rule xxd_p: medium {
  meta:
    description = "uses the xxd command to generate hex"

  strings:
    $xxd_p = "xxd -p"

  condition:
    filesize < 128KB and any of them
}

rule long_hex_var_multiple: high {
  meta:
    description = "contains multiple large hexadecimal string variables"

  strings:
    $assign = /\w{0,16}=["'][a-z0-9]{1024}/

  condition:
    filesize < 10MB and #assign > 3
}

rule long_hex_var: medium {
  meta:
    description = "contains a large hexadecimal string variable"

  strings:
    $assign = /\w{0,16}=["'][a-z0-9]{1024}/

  condition:
    filesize < 10MB and $assign
}
