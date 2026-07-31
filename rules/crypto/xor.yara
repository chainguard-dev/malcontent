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

    // plain-literal twin of $x_encode_, used only for counting: the leading
    // \w{0,16} makes $x_encode_ report one match per start offset, so #x_encode_
    // is not an occurrence count
    $c_encode_ = "xor_encode"

    $not_qemu = "Opcode_xor_encode"

  condition:
    // $not_qemu is a qemu-xtensa symbol name that contains "xor_encode", so it can only
    // excuse a $x_encode_ match -- every other spelling still counts on its own. Each
    // "Opcode_xor_encode" holds exactly one "xor_encode", so a higher count means the
    // file has a xor_encode that the qemu symbol does not account for.
    any of ($x_decode, $x_encode, $x_file, $x_decode_, $x_file_, $x_crypt) or ($x_encode_ and #c_encode_ > #not_qemu)
}
