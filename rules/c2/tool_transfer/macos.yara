private rule tool_transfer_macho {
  strings:
    $not_jar   = "META-INF/"
    $not_dwarf = "_DWARF"
    $not_kext  = "_.SYMDEF SORTED"

  condition:
    (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178) and none of ($not*)
}

rule macos_chflags_hidden: critical {
  meta:
    description = "dropper that hides it's payload using chflags"
    hash        = "e064158742c9a5f451e69b02e83eea9fb888623fafe34ff5b38036901d8419b4"
    filetypes   = "macho"

  strings:
    $c_curl    = "curl" fullword
    $c_chflags = "chflags" fullword
    $c_hidden  = "hidden" fullword
    $c_chmod   = "chmod" fullword

  condition:
    filesize < 5MB and all of them
}

rule cocoa_bundle_dropper: critical {
  meta:
    ref       = "https://www.huntress.com/blog/lightspy-malware-variant-targeting-macos"
    filetypes = "macho"

  strings:
    $bundle   = "NSBundle" fullword
    $url      = "NSURL" fullword
    $shared   = "/Users/Shared" fullword
    $aes      = "AES" fullword
    $download = "Download" fullword
    $platform = "isPlatformOrVariantPlatformVersionAtLeast" fullword

  condition:
    tool_transfer_macho and $shared and 5 of them
}
