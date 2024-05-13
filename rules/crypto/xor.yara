
rule xor_decode_encode : high {
  meta:
    description = "decodes/encodes XOR content"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_4b97 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"
  strings:
    $decode = /\w{0,16}XorDecode[\w]{0,32}/
    $encode = /\w{0,16}XorEncode[\w]{0,32}/
    $file = /\w{0,16}XorFile[\w]{0,32}/
    $decode_ = /\w{0,16}xor_decode[\w]{0,32}/
    $encode_ = /\w{0,16}xor_encode[\w]{0,32}/
    $file_ = /\w{0,16}xor_file[\w]{0,32}/
  condition:
    any of them
}
