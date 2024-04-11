
rule curl_value : notable {
	meta:
		description = "Invokes curl"
	strings:
		$ref = /curl [\w\.\- :\"\/]{0,64}/
	condition:
		$ref
}

rule curl_download_val : notable {
	meta:
		description = "Invokes curl to download a file"
	strings:
		$ref = /curl [\w\.\- :\"\/]{0,64}-[oO][\w\- :\"\/]{0,64}/
	condition:
		$ref
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
  condition:
    any of ($t_*) and none of ($not*)
}
