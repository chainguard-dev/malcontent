rule danger_crypto_miner: high {
  meta:
    hash_2023_Py_Trojan_NecroBot_0e60 = "0e600095a3c955310d27c08f98a012720caff698fe24303d7e0dcb4c5e766322"
    hash_2023_gcclib_xfitaarch        = "163f78541c2fbdad128997534ecc2ad31b112f779347c526dd4e071a608de85c"

  strings:
    $c3pool          = "c3pool"
    $crypto_pool     = "crypto-pool"
    $f2pool          = "f2pool"
    $hashvault       = "hashvault"
    $monero_hash     = "monerohash"
    $monero_pool     = "moneropool"
    $monero_mms      = "mms_message_content"
    $xmrpool         = "xmrpool"
    $normalhashing   = "\"normalHashing\": true,"
    $stratum         = "stratum://"
    $stratum_ssl     = "stratum+ssl://"
    $stratum_tcp     = "stratum+tcp://"
    $stratup_tls     = "stratum+tls://"
    $xmrig           = "xmrig"
    $support_xmr     = "supportxmr"
    $MONERO          = "MONERO"
    $donate_level    = "--donate-level"
    $tls_fingerprint = "--tls-fingerprint"
    $miner_name      = "miner_name"
    $miner_url       = "miner_url"
    $cryptonight     = "Cryptonight"
    $minergate       = "minergate"

  condition:
    filesize < 10485760 and 1 of them
}
