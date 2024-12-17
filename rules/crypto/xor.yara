rule xor_decode_encode: high {
  meta:
    description = "decodes/encodes XOR content"

  strings:
    $x_decode  = /\w{0,16}XorDecode[\w]{0,32}/
    $x_encode  = /\w{0,16}XorEncode[\w]{0,32}/
    $x_file    = /\w{0,16}XorFile[\w]{0,32}/
    $x_decode_ = /\w{0,16}xor_decode[\w]{0,32}/
    $x_encode_ = /\w{0,16}xor_encode[\w]{0,32}/
    $x_file_   = /\w{0,16}xor_file[\w]{0,32}/
    $x_crypt   = /\w{0,16}XorCrypt[\w]{0,32}/

    $not_qemu = "Opcode_xor_encode"

  condition:
    any of ($x*) and none of ($not*)
}
