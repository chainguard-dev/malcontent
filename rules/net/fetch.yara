
rule curl : notable {
	meta:
		description = "Invokes curl"
	strings:
		$ref = /curl [\w\- :\"\/]{0,64}-o[\w\- :\"\/]{0,64}/
	condition:
		$ref
}

rule curl_download : notable {
	meta:
		description = "Invokes curl to download a file"
	strings:
		$ref = /curl [\w\- :\"\/]{0,64}-[oO][\w\- :\"\/]{0,64}/
	condition:
		$ref
}

rule curl_agent : suspicious {
	meta:
		description = "Invokes curl with a custom user agent"
	strings:
		$ref = /curl [\w\- :\"\/]{0,64}-a[ "][\w\- :\"\/]{0,64}/
	condition:
		$ref
}

rule urllib_oneliner : suspicious {
  meta:
    hash_2023_installer_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
  strings:
    $urllib_req = "import urllib.request; urllib.request.urlretrieve"
  condition:
    any of them
}

rule suspicious_fetch_command : suspicious {
  meta:
    hash_2019_Macma_AgentB = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
    hash_2021_Macma_CDDS_UserAgent = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
    hash_2016_Eleanor_eleanr_save = "5dbbb91467e0f6e58497ae0c0c621a84a1f250bb856f3f9f139e70dedf1a32b7"
    hash_2018_MacOS_CoinTicker = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
    hash_2021_Gmera_Licatrade = "ad27ae075010795c04a6c5f1303531f3f2884962be4d741bf38ced0180710d06"
    hash_2021_trojan_Gafgyt_Mirai_tlduc_bashlite = "16bbeec4e23c0dc04c2507ec0d257bf97cfdd025cd86f8faf912cea824b2a5ba"
    hash_2021_trojan_Gafgyt_DDoS = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
    hash_2021_trojan_Gafgyt_23DZ = "b34bb82ef2a0f3d02b93ed069fee717bd1f9ed9832e2d51b0b2642cb0b4f3891"
  strings:
    $curl_d = /curl +-[ALCdOok]/
    $curl_insecure = /curl [\- \w]*--insecure/
    $curl_silent = /curl [\- \w]*--silent/
    $kinda_curl_silent_insecure = "--silent --insecure"
    $kinda_curl_silent_k = "-k --insecure"
    $kinda_curl_k_q = "-k -q"
    $wget_insecure = "wget --no-check-certificate"
  condition:
    any of them
}


rule executable_calls_fetch_tool {
  meta:
    hash_2021_trojan_Mirai_3_Gafgyt = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2021_trojan_Gafgyt_Mirai_tlduc_bashlite = "16bbeec4e23c0dc04c2507ec0d257bf97cfdd025cd86f8faf912cea824b2a5ba"
    hash_2021_trojan_Gafgyt_DDoS = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
    hash_2023_Linux_Malware_Samples_1fce = "1fce1d5b977c38e491fe84e529a3eb5730d099a4966c753b551209f4a24524f3"
    hash_2021_trojan_Mirai_dclea = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"
    hash_2021_miner_xxlgo = "20e4c4893ed1faa9a50b0a4ba5fa0062d5178b635222849eeafa53e8c5c0d8c8"
    hash_2021_miner_gijuf = "24ee0e3d65b0593198fbe973a58ca54402b0879d71912f44f4b831003a5c7819"
    hash_2021_trojan_miner_oztkc = "2f85ca8f89dfb014b03afb11e5d2198a8adbae1da0fd76c81c67a81a80bf1965"
  strings:
    $t_curl = "curl -"
    $t_wget = "wget -"
    $t_wget_http = "wget http"
    $t_quiet_output = "-q -O "
    $t_kinda_curl_o = "url -o "
    $t_kinda_curl_O = "url -O "
    $t_kinda_curl_silent_insecure = "silent --insecure"
    $t_kinda_curl_qk = "-k -q"
    $t_ftp = "ftp -"
    $t_tftp = "tftp "
    $t_ftpget = "ftpget " fullword
    $not_compdef = "#compdef"
    $not_gnu = "GNU Wget"
    $not_wget_ = "wget_"
    $not_syntax = "syntax file"
    $not_syntax_menu = "Syntax menu"
    $not_c_string = "%wget"
    $not_curlopt = "CURLOPT"
    $not_program = "@(#)PROGRAM:"
    $hash = "#"
  condition:
    any of ($t_*) and not $hash at 0 and none of ($not*)
}
