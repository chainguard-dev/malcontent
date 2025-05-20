include "rules/global.yara"

import "math"

rule go_aes: high {
  meta:
    description = "go binary packed with AES"
    filetypes   = "elf,macho"

  strings:
    $aes     = "crypto/aes"
    $go      = "go:buildid"
    $decrypt = "NewCFBDecrypter"

  condition:
    small_binary and math.entropy(1, filesize) >= 7 and all of them
}
