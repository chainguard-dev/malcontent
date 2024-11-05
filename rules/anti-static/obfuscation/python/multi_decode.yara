rule multi_decode_3: high {
  meta:
    description = "multiple (3+) levels of decoding"
    filetypes   = "py"

  strings:
    $return              = "return"
    $decode_or_b64decode = /\.[b64]{0,3}decode\(.{0,256}\.[b64]{0,3}decode\(.{0,256}\.[b64]{0,3}decode/

  condition:
    filesize < 1MB and all of them
}

rule multi_decode: medium {
  meta:
    description = "multiple (2) levels of decoding"
    filetypes   = "py"

  strings:
    $return              = "return"
    $decode_or_b64decode = /\.[b64]{0,3}decode\(.{0,32}\.[b64]{0,3}decode\(/

  condition:
    filesize < 1MB and all of them
}

