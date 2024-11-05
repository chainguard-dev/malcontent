rule fernet_base64: high {
  meta:
    description = "Decodes base64, uses Fernet"
    filetypes   = "py"

  strings:
    $fernet     = "Fernet" fullword
    $fernet2    = "fernet" fullword
    $bdecode_64 = "b64decode" fullword
    $bdecode_32 = "b32decode" fullword
    $o1         = "decode()"
    $o2         = "decompress("
    $o4         = "bytes.fromhex"
    $o5         = "decrypt("
    $o6         = "exec("
    $o7         = "eval("

  condition:
    filesize < 2MB and any of ($fernet*) and any of ($bdecode*) and any of ($o*)
}
