
rule download_sites : suspicious {
  meta:
    ref = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_suspicious.yar#L1001"
    description = "References known file hosting site"
  strings:
    $d_privatebin = /[\w\.]+privatebin[\w\.]+/
    $d_pastecode_dot = /pastecode\.[\w\.]+/
    $d_discord = "cdn.discordapp.com"
    $d_pastebinger = "paste.bingner.com"
    $d_transfer_sh = "transfer.sh"
    $d_rentry = "rentry.co" fullword
    $d_penyacom = "penyacom"
    $d_controlc = "controlc.com"
    $d_anotepad = "anotepad.com"
    $d_privnote = "privnote.com"
    $d_hushnote = "hushnote"
    $not_mozilla = "download.mozilla.org"
    $not_google = "dl.google.com"
    $not_manual = "manually upload"
    $not_paste_go = "paste.go"
    $not_netlify = "netlify.app"
  condition:
    any of ($d_*) and none of ($not*)
}

rule pastebin : notable {
  meta:
    ref = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_suspicious.yar#L1001"
    description = "References known file hosting site"
  strings:
    $d_pastebin = /[\w\.]{1,128}astebin[\w\.\/]{1,128}/
  condition:
    any of ($d_*)
}

rule http_dropper_url : notable {
  meta:
    ref = "https://unfinished.bike/qubitstrike-and-diamorphine-linux-kernel-rootkits-go-mainstream"
  strings:
    $program_url = /https*:\/\/[\w\.]{1,128}\/[\/\.\w]{1,128}\.(sh|gz|zip|Z|exe|bz2|py|bin|plist)/ fullword
    $not_gstatic = "https://www.gstatic.com/chrome"
    $not_sentry = "https://github.com/getsentry/sentry"
    $not_apple = "suconfig.apple.com"
    $not_perl = "http://www.perl.com"
  condition:
    $program_url and none of ($not*)
}

rule executable_url : suspicious {
  strings:
    $xecURL = "xecURL"
    $xecUrl = "xecUrl"
    $xecutableUrl = "xecutableUrl"
    $not_set = "setExecutable"
  condition:
    any of ($xec*) and none of ($not*)
}
