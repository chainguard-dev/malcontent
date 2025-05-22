rule download_sites: high {
  meta:
    ref         = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_high.yar#L1001"
    description = "References known file hosting site"

  strings:
    $d_privatebin    = /[\w\.]+privatebin[\w\.]{1,4}\//
    $d_pastecode_dot = /pastecode\.[\w\.]{2,16}/
    $d_paste_dot     = /\/paste\.[\w\.]{2,3}\//
    $d_api_paste_dot = /\/api\.paste\.[\w\.]{2,3}\//
    $d_storj         = /link\.storjshare\.io[\/\w\.]{0,64}/

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
    $not_misp_galaxy = "misp-galaxy:"

  condition:
    any of ($d_*) and none of ($not*)
}

rule base64_download_site: high {
  meta:
    description = "References known file hosting site, base64 encoded"

  strings:
    $ = "privatebin" base64
    $ = "pastebin" base64
    $ = "api.paste." base64
    $ = "cdn.discordapp.com" base64
    $ = "privnote.com" base64
    $ = "hushnote" base64
    $ = "gist.githubusercontent.com" base64

  condition:
    any of them
}

rule pastebin: medium {
  meta:
    ref         = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_high.yar#L1001"
    description = "References known file hosting site"

  strings:
    $d_pastebin = /[\w\.]{1,128}astebin[\w\.\/]{1,128}/

    $not_misp_galaxy = "misp-galaxy:"

  condition:
    any of ($d_*) and none of ($not*)
}

rule program_dropper_url: medium {
  meta:
    description = "downloads program from a hardcoded URL"
    ref         = "https://unfinished.bike/qubitstrike-and-diamorphine-linux-kernel-rootkits-go-mainstream"

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

rule download_and_exec: high {
  strings:
    $down_exec = "down-n-exec" fullword
    $e_process = "process"
    $e_Process = "Process"
    $e_exec    = "exec"

  condition:
    filesize < 2MB and $down_exec and any of ($e*)
}

rule http_archive_url: medium {
  meta:
    description = "accesses hardcoded archive file endpoint"

  strings:
    $ref         = /https{0,1}:\/\/[\w\.]{0,160}[:\/\w\_\-\?\@=]{6,160}\.(zip|tar|tgz|gz|xz)/ fullword
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
    filetypes   = "elf,macho"

  strings:
    $ref         = /https{0,1}:\/\/[\w\.]{0,160}[:\/\w\_\-\?\@=]{6,160}\.(zip|tar|tgz|gz|xz)/ fullword
    $not_foo_bar = "http://foo/bar.tar"

  condition:
    smallerBinary and any of ($ref*) and none of ($not*)
}
