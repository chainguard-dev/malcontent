
rule download_sites : suspicious {
  meta:
    ref = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_suspicious.yar#L1001"
	description = "References known file hosting site"
  strings:
 //   $d_pastebin = /[\w\.]+astebin[\w\.]+/
    $d_privatebin = /[\w\.]+privatebin[\w\.]+/
   // $d_paste_dot = /paste\.[\w\.]{2,3}/
    $d_pastecode_dot = /pastecode\.[\w\.]+/
    $d_discord = "cdn.discordapp.com"
    $d_transfer_sh = "transfer.sh"
    $d_rentry = "rentry.co"
    $d_penyacom = "penyacom"
    $d_controlc = "controlc.com"
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
    $d_pastebin = "pastebin.com"
  condition:
    any of ($d_*)
}



rule ngrok : notable {
  meta:
    ref = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_suspicious.yar#L1001"
	description = "References known file hosting site"
  strings:
    $d_pastebin = "ngrok.io"
  condition:
    any of ($d_*)
}


rule google_drive : notable {
  meta:
    ref = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_suspicious.yar#L1001"
	description = "References known file hosting site"
  strings:
    $d_gdrive = "drive.google.com"
  condition:
    any of ($d_*)
}
