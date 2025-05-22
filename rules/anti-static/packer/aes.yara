import "math"

private rule smallBinary {
  condition:
    // matches ELF or machO binary
    filesize > 1MB and filesize < 8MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

rule go_aes: high {
  meta:
    description = "go binary packed with AES"
    filetypes   = "elf,macho"

  strings:
    $aes     = "crypto/aes"
    $go      = "go:buildid"
    $decrypt = "NewCFBDecrypter"

  condition:
    smallBinary and math.entropy(1, filesize) >= 7 and all of them
}
