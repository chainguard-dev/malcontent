
rule download_sites : suspicious {
  meta:
    ref = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_suspicious.yar#L1001"
	description = "References known file hosting site"
  strings:
    $d_pastebin = /[\w\.]+astebin[\w\.]+/
    $d_privatebin = /[\w\.]+privatebin[\w\.]+/
    $d_paste_dot = /paste\.[\w\.]+/
    $d_pastecode_dot = /pastecode\.[\w\.]+/
    $d_google_drive = "drive.google.com"
    $d_discord = "cdn.discordapp.com"
    $d_transfer_sh = "transfer.sh"
    $d_ngrok_io = "ngrok.io"
    $d_rentry = "rentry.co"
    $d_penyacom = "penyacom"
    $d_controlc = "controlc.com"
    $d_privnote = "privnote.com"
    $d_hushnote = "hushnote"
    $not_mozilla = "download.mozilla.org"
    $not_google = "dl.google.com"
    $not_manual = "manually upload"
  condition:
    any of ($d_*) and none of ($not*)
}
