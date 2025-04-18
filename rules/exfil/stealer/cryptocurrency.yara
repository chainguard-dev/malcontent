rule js_cryptcurrency_stealer: high {
  meta:
    description = "may steal cryptocurrency"

  strings:
    $c_btc        = "BTC" fullword
    $c_eth        = "ETH" fullword
    $c_trx        = "TRX-USDT" fullword
    $c_xrp        = "XRP" fullword
    $c_sol        = "SOL" fullword
    $c_soltoken   = "SOLToken" fullword
    $o_send       = "send" fullword
    $o_atob       = "atob(" fullword
    $o_address    = "address" fullword
    $o_send_coin  = "Send Coin" fullword
    $o_sendcoin   = "sendCoin"
    $o_types_send = "TYPES.SEND" fullword

  condition:
    filesize < 50KB and 3 of ($c*) and 3 of ($o*)
}
