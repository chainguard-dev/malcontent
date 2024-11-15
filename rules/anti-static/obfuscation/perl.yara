rule generic_obfuscated_perl: medium {
  meta:
    description = "Obfuscated PERL code"

    filetypes = "pl"

  strings:
    $unpack_nospace = "pack'" fullword
    $unpack         = "pack '" fullword
    $unpack_paren   = "pack(" fullword
    $reverse        = "reverse "
    $sub            = "sub "
    $eval           = "eval{"
    $not_unpack_a   = "unpack('aaaaaaaa'"
    $not_unpack_i   = "unpack(\"i\","

  condition:
    filesize < 32KB and $eval and 3 of them and none of ($not*)
}
