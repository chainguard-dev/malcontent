rule danger_crypto_miner: high {
  meta:
    description = "crypto miner, like xmrig"

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

    $not_pypi_index = "testpack-id-lb001"

  condition:
    filesize < 10485760 and 2 of them and none of ($not*)
}
