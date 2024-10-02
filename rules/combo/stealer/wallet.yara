
rule crypto_stealer_names : critical {
  meta:
    description = "makes HTTPS connections and references multiple wallets by name"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
  strings:
    $http = "http"
    $w_mm = "Metamask"
    $w_bw = "BraweWallet"
    $w_bv = "BraveWallet"
    $w_r = "Ronin"
    $w_nw = "NiftyWallet"
    $w_cw = "CloverWallet"
    $w_ms = "MonstraWallet"
    $w_oa = "OasisWallet"
    $w_bn = "BinanceChain"
    $w_ir = "Iridium"
    $w_tl = "TronLink"
    $w_hycon = "Hycon L"
    $w_coin = "Coinbas"
    $w_wallet = /[\w\/]{0,32}\/\.walle[\w\/]{0,16}/
    $w_trezor = "Trezor"
    $w_exodus = "Exodus"
	$w_exodus_2 = "aholpfdial"
    $w_coinomi = "Coinomi"

    $not_cats = /\"cats\": \[[^]]{0,64}/
    $not_description = /\"description\": "([^"]{0,64})"/
    $not_dom = /\"dom\": "([^"]{0,64})"/
    $not_icon = /\"icon\": "([^"]{0,64})"/
    $not_js  = /\"js\": \{[^}]{0,64}/
    $not_scriptsrc = /\"scriptSrc\": "([^"]{0,64})"/
    $not_website = /\"website\": "([^"]{0,64})"/
  condition:
    $http and 2 of ($w*) and none of ($not*)
}


rule crypto_extension_stealer : critical {
  meta:
    description = "makes HTTPS connections and references multiple Chrome crypto wallet extensions"
  strings:
    $http = "http"

	$w_metamask1 = "nkbihfbeogae"
	$w_metamask2 = "ejbalbakoplch"
	$w_bnb = "fhbohimaelbohp"
	$w_coinbase = "hnfanknocfeof"
	$w_tronlink = "ibnejdfjmmkpc"
	$w_phantom = "bfnaelmomeimh"
	$w_coin98 = "aeachknmefph"
	$w_crypto_com = "mccdpekplomjjkc"
	$w_kaia = "gpafnldhgmapag"
	$w_rabby = "ebolmdjonilk"
	$w_argent = "ohmabehhmhfoo"
	$w_exodus = "mihkjbmgjidlc"

    $not_cats = /\"cats\": \[[^]]{0,64}/
    $not_description = /\"description\": "([^"]{0,64})"/
    $not_dom = /\"dom\": "([^"]{0,64})"/
    $not_icon = /\"icon\": "([^"]{0,64})"/
    $not_js  = /\"js\": \{[^}]{0,64}/
    $not_scriptsrc = /\"scriptSrc\": "([^"]{0,64})"/
    $not_website = /\"website\": "([^"]{0,64})"/
  condition:
    $http and 3 of ($w*) and none of ($not*)
}
