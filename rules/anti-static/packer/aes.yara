import "math"

include "rules/global/global.yara"

rule go_aes: high {
  meta:
    description = "go binary packed with AES"
    filetypes   = "elf,macho"

  strings:
    $aes     = "crypto/aes"
    $go      = "go:buildid"
    $decrypt = "NewCFBDecrypter"

  condition:
    global_small_binary and math.entropy(1, filesize) >= 7 and all of them
}
