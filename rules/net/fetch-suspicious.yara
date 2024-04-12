
rule curl_agent_val : suspicious {
	meta:
		description = "Invokes curl with a custom user agent"
	strings:
		$ref = /curl [\w\.\- :\"\/]{0,64}-a[ "][\w\- :\"\/]{0,64}/
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

rule suspicious_fetch_command_val : suspicious {
  meta:
	description = "suspicious fetch command"
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
    $c_curl_d = /curl [\- \w]{0,16}-[dOok][\/\- \w\%\(\{\}\'\"\)\$]{0,128}/
    $c_curl_insecure = /curl [\- \w]{0,128}--insecure[\/\- \w\%\(\{\}\'\"\)\$]{0,128}/
    $c_kinda_curl_silent_insecure = "--silent --insecure"
    $c_kinda_curl_silent_k = "-k --insecure"
    $c_kinda_curl_k_q = "-k -q"
    $c_wget_insecure = /wget --no-check-certificate[\/\- \w\%\(\{\}\'\"\)\$]{0,128}/

	$not_curl_response_code = "%{response_code}"
  condition:
    any of ($c*) and none of ($not*)
}

