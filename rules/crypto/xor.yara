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
    // $not_qemu is a qemu-xtensa symbol name that contains "xor_encode", so it can only
    // excuse a $x_encode_ match -- every other spelling still counts on its own.
    any of ($x_decode, $x_encode, $x_file, $x_decode_, $x_file_, $x_crypt) or ($x_encode_ and not $not_qemu)
}
