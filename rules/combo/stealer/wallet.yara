
rule crypto_stealer : critical {
  meta:
	description = "makes HTTPS connections and references multiple wallets"
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
	$w_coinomi = "Coinomi"
  condition:
	$http and 2 of ($w*)
}
