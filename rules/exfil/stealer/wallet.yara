rule crypto_stealer_names: critical {
  meta:
    description = "makes HTTPS connections and references multiple wallets by name"

  strings:
    $http       = "http"
    $w_mm       = "Metamask"
    $w_bw       = "BraweWallet"
    $w_bv       = "BraveWallet"
    $w_r        = "Ronin"
    $w_nw       = "NiftyWallet"
    $w_cw       = "CloverWallet"
    $w_ms       = "MonstraWallet"
    $w_oa       = "OasisWallet"
    $w_bn       = "BinanceChain"
    $w_ir       = "Iridium"
    $w_tl       = "TronLink"
    $w_hycon    = "Hycon L"
    $w_coin     = /Coinbas\w{0,32}/
    $w_wallet   = /[\w\/]{0,32}\/\.walle[\w\/]{0,16}/
    $w_trezor   = "Trezor"
    $w_exodus   = "Exodus"
    $w_exodus_2 = "aholpfdial"
    $w_coinomi  = "Coinomi"

    $not_cats        = /\"cats\": \[[^]]{0,64}/
    $not_description = /\"description\": "([^"]{0,64})"/
    $not_dom         = /\"dom\": "([^"]{0,64})"/
    $not_icon        = /\"icon\": "([^"]{0,64})"/
    $not_js          = /\"js\": \{[^}]{0,64}/
    $not_scriptsrc   = /\"scriptSrc\": "([^"]{0,64})"/
    $not_website     = /\"website\": "([^"]{0,64})"/
    $not_geth_mod    = "github.com/ethereum/go-ethereum"
    $not_clef        = "github.com/ethereum/go-ethereum/cmd/clef/main.go"
    $not_geth        = "github.com/ethereum/go-ethereum/cmd/geth/main.go"

  condition:
    filesize < 100MB and $http and 2 of ($w*) and none of ($not*)
}

rule crypto_extension_stealer: critical {
  meta:
    description = "makes HTTPS connections and references multiple Chrome crypto wallet extensions"

  strings:
    $http = "http"

    $w_metamask1  = "nkbihfbeogae"
    $w_metamask2  = "ejbalbakoplch"
    $w_bnb        = "fhbohimaelbohp"
    $w_coinbase   = "hnfanknocfeof"
    $w_tronlink   = "ibnejdfjmmkpc"
    $w_phantom    = "bfnaelmomeimh"
    $w_coin98     = "aeachknmefph"
    $w_crypto_com = "mccdpekplomjjkc"
    $w_kaia       = "gpafnldhgmapag"
    $w_rabby      = "ebolmdjonilk"
    $w_argent     = "ohmabehhmhfoo"
    $w_exodus     = "mihkjbmgjidlc"

    $not_cats        = /\"cats\": \[[^]]{0,64}/
    $not_description = /\"description\": "([^"]{0,64})"/
    $not_dom         = /\"dom\": "([^"]{0,64})"/
    $not_icon        = /\"icon\": "([^"]{0,64})"/
    $not_js          = /\"js\": \{[^}]{0,64}/
    $not_scriptsrc   = /\"scriptSrc\": "([^"]{0,64})"/
    $not_website     = /\"website\": "([^"]{0,64})"/

  condition:
    filesize < 100MB and $http and 3 of ($w*) and none of ($not*)
}
