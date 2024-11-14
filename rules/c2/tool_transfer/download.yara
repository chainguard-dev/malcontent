rule download_sites: high {
  meta:
    ref                        = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_high.yar#L1001"
    description                = "References known file hosting site"
    hash_2023_zproxy_1_0_setup = "f3d7eec1ae2eba61715fd0652fa333acc2e4c0d517579392043880aa2f158b62"

    hash_2024_2024_GitHub_Clipper_raw = "e9f89885876c1958bc6eede3373e4f3c4d76a5bc35a247fb7531b757798cb032"

  strings:
    $d_privatebin    = /[\w\.]+privatebin[\w\.]{1,4}\//
    $d_pastecode_dot = /pastecode\.[\w\.]{2,16}/
    $d_paste_dot     = /\/paste\.[\w\.]{2,3}\//
    $d_discord       = "cdn.discordapp.com"
    $d_pastebinger   = "paste.bingner.com"
    $d_transfer_sh   = "transfer.sh"
    $d_rentry        = "rentry.co" fullword
    $d_pastebin      = /pastebin\.[\w]{2,3}[\w\/]{0,16}/ fullword
    $d_penyacom      = "penyacom"
    $d_controlc      = "controlc.com"
    $d_anotepad      = "anotepad.com"
    $d_privnote      = "privnote.com"
    $d_hushnote      = /hushnote[\.\w\/]{3,16}/
    $d_000webhostapp = "000webhostapp"
    $not_mozilla     = "download.mozilla.org"
    $not_google      = "dl.google.com"
    $not_manual      = "manually upload"
    $not_paste_go    = "paste.go"
    $not_netlify     = "netlify.app"

  condition:
    any of ($d_*) and none of ($not*)
}

rule pastebin: medium {
  meta:
    ref         = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_high.yar#L1001"
    description = "References known file hosting site"

    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"

  strings:
    $d_pastebin = /[\w\.]{1,128}astebin[\w\.\/]{1,128}/

  condition:
    any of ($d_*)
}

rule program_dropper_url: medium {
  meta:
    description              = "downloads program from a hardcoded URL"
    ref                      = "https://unfinished.bike/qubitstrike-and-diamorphine-linux-kernel-rootkits-go-mainstream"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"

  strings:
    $program_url = /https*:\/\/[\w\.]{1,128}\/[\/\.\w]{1,128}\.(sh|gz|zip|Z|exe|bz2|py|bin|plist)/ fullword
    $not_gstatic = "https://www.gstatic.com/chrome"
    $not_sentry  = "https://github.com/getsentry/sentry"
    $not_apple   = "suconfig.apple.com"
    $not_perl    = "http://www.perl.com"

  condition:
    $program_url and none of ($not*)
}

rule executable_url: high {
  strings:
    $xecURL       = "xecURL"
    $xecUrl       = "xecUrl"
    $xecutableUrl = "xecutableUrl"
    $not_set      = "setExecutable"

  condition:
    any of ($xec*) and none of ($not*)
}

rule http_archive_url: medium {
  meta:
    description = "accesses hardcoded archive file endpoint"

  strings:
    $ref         = /https*:\/\/[\w\.]{0,160}[:\/\w\_\-\?\@=]{6,160}\.(zip|tar|tgz|gz|xz)/ fullword
    $not_foo_bar = "http://foo/bar.tar"

  condition:
    any of ($ref*) and none of ($not*)
}

private rule smallerBinary {
  condition:
    // matches ELF or machO binary
    filesize < 10MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

rule http_archive_url_higher: high {
  meta:
    description = "accesses hardcoded archive file endpoint"

  strings:
    $ref         = /https*:\/\/[\w\.]{0,160}[:\/\w\_\-\?\@=]{6,160}\.(zip|tar|tgz|gz|xz)/ fullword
    $not_foo_bar = "http://foo/bar.tar"

  condition:
    smallerBinary and any of ($ref*) and none of ($not*)
}

