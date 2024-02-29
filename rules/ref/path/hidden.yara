
rule dynamic_hidden_path : notable {
	meta:
		description = "References a hidden file that can be generated dynamically"
		ref = "https://objective-see.org/blog/blog_0x73.html"
	strings:
		$ref = /%s\/\.[a-z][\w-]{0,32}/
		$config = "%s/.config"
	condition:
		$ref and not $config
}

rule static_hidden_path {
	meta:
		description = "Possible hidden file path"
	strings:
		$ref = /\/[a-z]{3,10}[\w\/]{0,24}\/\.[\w\_\-\.]{0,16}/
	condition:
		$ref
}

rule hidden_path {
  meta:
	description = "Hidden file path in a system directory"
    hash_2016_trojan_Eleanor_eleanr_A_timegrabber = "2532a3feeb656c5467bedfcc0cb4bfa3eb26bcc36b33a51b13f38ae2eef22797"
    hash_2016_trojan_Eleanor_eleanr_A_plist = "a975d8232b264e2981559b2e76f779335af37605ca300906fea737f125914c4b"
    hash_2016_Eleanor_eleanr_check_hostname = "8b1d98777bd98faeeaed9f2289d8dba8e34c46c694f6f31141404853c3af239d"
    hash_2016_Eleanor_eleanr_integritycheck = "049716023e99821230bb8f9b3fa58722ad6e5a0af2c3b8b9c3fe9c09b4bb0141"
    hash_2016_Eleanor_eleanr_save = "5dbbb91467e0f6e58497ae0c0c621a84a1f250bb856f3f9f139e70dedf1a32b7"
    hash_2016_Eleanor_eleanr_script = "2c752b64069e9b078103adf8f5114281b7ce03f1ca7a995228f180140871999e"
    hash_2016_Eleanor_eleanr_storage = "8cee04d45b01743303f6e6e999483cd3f864643c6344d0a46196a67d343cd2ae"
    hash_2018_MacOS_CoinTicker = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
    hash_2018_MacOS_Installer = "939cd1780d360792e6df92f415627c4c099bead6a97426a9f49ab179f5e4c47d"
    hash_2019_Cointrazer_nytyntrun = "eacf7e3865e9995fd5fe74e61b2073441cba4029610cae739b2006de8e5787dc"
    hash_2020_CoinMiner_nbtoz = "741af7d54a95dd3b4497c73001e7b2ba1f607d19d63068b611505f9ce14c7776"
    hash_2020_MacOS_TinkaOTP = "90fbc26c65e4aa285a3f7ee6ff8a3a4318a8961ebca71d47f51ef0b4b7829fd0"
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
    hash_2021_trojan_Gafgyt_malxmr = "1b5bd0d4989c245af027f6bc0c331417f81a87fff757e19cdbdfe25340be01a6"
    hash_2021_gjif_tsunami_Gafygt = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
    hash_2021_Gmera_Licatrade = "ad27ae075010795c04a6c5f1303531f3f2884962be4d741bf38ced0180710d06"
    hash_2021_trojan_Mirai_dclea = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"
    hash_2021_trojan_Mirai_gsjmm = "dcd318efe5627e07a8eda9104ede1f510e43f5c0ae7f74d411137e1174f2844b"
    hash_2021_Tsunami_gjirtfg = "553ac527d6a02a84c787fd529ea59ce1eb301ddfb180d89b9e62108d92894185"
    hash_2021_Tsunami_Kaiten = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2021_Tsunami_Kaiten_ujrzc = "7a60c84fb34b2b3cd7eed3ecd6e4a0414f92136af656ed7d4460b8694f2357a7"
  strings:
    $crit = /[\w\/\.]{0,32}\/(tmp|usr\/\w{0,8}|bin|lib|LaunchAgents|lib64|var|etc|shm|mqueue|spool|log|Users|Movies|Music|WebServer|Applications|Shared|Library|System)\/\.\w[\w\-\.]{0,16}/
    $not_network_manager = "org.freedesktop.NetworkManager"
    $not_X11 = "/tmp/.X11-unix"
    $not_cpp = "/tmp/.cpp.err"
    $not_factory = "/Library/.FactoryMacCheckEnabled"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_compdef = "#compdef"
    $not_kandji = "/tmp/.io.kandji.passport-did-boot"
    $not_cargo = "/.cargo"
    $not_sandbox_profile = "andbox profile"
  condition:
    $crit and none of ($not*)
}

rule hidden_library : suspicious {
  meta:
	description = "Hidden file path in a Library directory"
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2020_MacOS_TinkaOTP = "90fbc26c65e4aa285a3f7ee6ff8a3a4318a8961ebca71d47f51ef0b4b7829fd0"
    hash_2016_Eleanor_eleanr_check_hostname = "8b1d98777bd98faeeaed9f2289d8dba8e34c46c694f6f31141404853c3af239d"
    hash_2016_Eleanor_eleanr_integritycheck = "049716023e99821230bb8f9b3fa58722ad6e5a0af2c3b8b9c3fe9c09b4bb0141"
    hash_2016_Eleanor_eleanr_save = "5dbbb91467e0f6e58497ae0c0c621a84a1f250bb856f3f9f139e70dedf1a32b7"
    hash_2016_Eleanor_eleanr_script = "2c752b64069e9b078103adf8f5114281b7ce03f1ca7a995228f180140871999e"
    hash_2016_Eleanor_eleanr_storage = "8cee04d45b01743303f6e6e999483cd3f864643c6344d0a46196a67d343cd2ae"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
  strings:
    $hidden_library = /\/Library\/\.\w{1,128}/
    $not_dotdot = "/Library/../"
    $not_private = "/System/Library/PrivateFrameworks/"
  condition:
    $hidden_library and none of ($not*)
}
