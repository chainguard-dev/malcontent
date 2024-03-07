
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
    hash_2023_installer_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2021_malxmr = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
    hash_2021_trojan_Gafgyt_Mirai_tlduc_bashlite = "16bbeec4e23c0dc04c2507ec0d257bf97cfdd025cd86f8faf912cea824b2a5ba"
    hash_2021_trojan_Gafgyt_DDoS = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
    hash_2021_trojan_Gafgyt_U = "3eb78b49994cf3a546f15a7fbeaf7e8b882ebd223bce149ed70c96aab803521a"
    hash_2023_Linux_Malware_Samples_525f = "525f97d2e16e8a847ff20b88d113ba73a7b364b921ac7e6bdbde82f6a7a8aee4"
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
  meta:
    hash_2023_KandyKorn_Discord = "2360a69e5fd7217e977123c81d3dbb60bf4763a9dae6949bc1900234f7762df1"
    hash_2023_stealer_hashbreaker = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_blackcat_x64 = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2020_FinSpy_installer = "80d6e71c54fb3d4a904637e4d56e108a8255036cbb4760493b142889e47b951f"
    hash_2020_finspy_logind_installer = "ac414a14464bf38a59b8acdfcdf1c76451c2d79da0b3f2e53c07ed1c94aeddcd"
    hash_2013_MacOS_installer = "962b879e9c5c821a0f6ca1c1a0f66912bd7e03b99da177b3c3a85de140140f02"
    hash_2023_RustBucket_Stage_3 = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
  strings:
    $xecURL = "xecURL"
    $xecUrl = "xecUrl"
    $xecutableUrl = "xecutableUrl"
	$not_set = "setExecutable"
  condition:
    any of ($xec*) and none of ($not*)
}
