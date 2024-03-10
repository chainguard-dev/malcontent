rule proxy_http_aes_terminal_combo : notable {
  meta:
    hash_2020_OSX_CoinMiner_xbppt = "a2909754783bb5c4fd6955bcebc356e9d6eda94f298ed3e66c7e13511275fbc4"
    hash_2023_CoinMiner_lauth = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"
    hash_2021_CoinMiner_TB_Camelot = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2021_ANDR_miner_eomap = "329255e33f43e6e9ae5d5efd6f5c5745c35a30d42fb5099beb51a6e40fe9bd76"
    hash_2021_miner_nyoan = "9f059b341ac4e2e00ab33130fea5da4b1390f980d3db607384d87e736f30273e"
    hash_2021_miner_vsdhx = "caa114893cf5cb213b39591bbcb72f66ee4519be07269968e714a8d3f24c3382"
    hash_2021_miner_fdxme = "d1a95861c6b9836c0c3d8868019054931d1339ae896ad11575e99d91a358696d"
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
  strings:
    $isatty = "isatty"
    $socks_proxy = "socks proxy"
    $socks = "SOCKS"
    $http = "http://"
    $http_req = "http request"
    $aes_gcm = "AESGCM"
    $aes_256 = "AES-256"
  condition:
    filesize < 26214400 and 85% of them
}
