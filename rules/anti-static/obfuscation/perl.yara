rule generic_obfuscated_perl: medium {
  meta:
    description               = "Obfuscated PERL code"
    hash_1980_FruitFly_A_205f = "205f5052dc900fc4010392a96574aed5638acf51b7ec792033998e4043efdf6c"
    hash_1980_FruitFly_A_9968 = "9968407d4851c2033090163ac1d5870965232bebcfe5f87274f1d6a509706a14"
    hash_1980_FruitFly_A_bbbf = "bbbf73741078d1e74ab7281189b13f13b50308cf03d3df34bc9f6a90065a4a55"
    filetypes                 = "pl"

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
