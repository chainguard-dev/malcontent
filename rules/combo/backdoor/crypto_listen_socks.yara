rule socks_crypto_listener : notable {
  meta:
    hash_2020_OSX_CoinMiner_xbppt = "a2909754783bb5c4fd6955bcebc356e9d6eda94f298ed3e66c7e13511275fbc4"
    hash_2023_CoinMiner_lauth = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"
    hash_hash_2015_trojan_Eleanor_conn = "5c16f53276cc4ef281e82febeda254d5a80cd2a0d5d2cd400a3e9f4fc06e28ad"
    hash_2015_data_storage = "329f79d9b21b186550ece1b5fbdc6adb2947fd83e3a02e662bd9ed27aa206074"
    hash_2021_miner_gkqjh = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2021_miner_malxmr = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
    hash_2021_CoinMiner_TB_Camelot = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2021_miner_KB_Elvuz = "0b1c49ec2d53c4af21a51a34d9aa91e76195ceb442480468685418ba8ece1ba6"
    hash_2021_miner_malxmr_sbepq = "0d7960a39b92dad88986deea6e5861bd00fb301e92d550c232aebb36ed010e46"
    hash_2021_miner_xxlgo = "20e4c4893ed1faa9a50b0a4ba5fa0062d5178b635222849eeafa53e8c5c0d8c8"
    hash_2021_miner_gijuf = "24ee0e3d65b0593198fbe973a58ca54402b0879d71912f44f4b831003a5c7819"
    hash_2021_miner_egipp = "47a4ca5b1b6a2c0c7914b342f668b860041ec826d2ac85825389dba363797431"
    hash_2021_miner_nyoan = "9f059b341ac4e2e00ab33130fea5da4b1390f980d3db607384d87e736f30273e"
    hash_2021_miner_vsdhx = "caa114893cf5cb213b39591bbcb72f66ee4519be07269968e714a8d3f24c3382"
    hash_2021_miner_fdxme = "d1a95861c6b9836c0c3d8868019054931d1339ae896ad11575e99d91a358696d"
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
    hash_2021_CoinMiner_Camelot = "fadc69995b9f837837595d73be8dce1bbccf0b709d0d8bb2cadf1c90b46763cf"
  strings:
    $s_socks = "SOCKS" fullword
    $s_SOCKS5 = "SOCKS5" fullword
    $s_socks5 = "socks5" fullword
    $f_listen = "listen" fullword
    $f_crypto = "crypto"
    $not_ssh = "SSH_AUTH_SOCK"
    $not_kolide = "KOLIDE_LAUNCHER_OPTION"
    $not_launcher = "LAUNCHER_DEBUG"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_nc = "usage: nc"
    $not_kitty = "KITTY_KITTEN_RUN_MODULE"
    $not_logger = "log.(*Logger)"
	$not_js = "function("
  condition:
    filesize < 26214400 and any of ($s*) and all of ($f*) and none of ($not*)
}
