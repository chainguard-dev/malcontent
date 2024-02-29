rule macos_proxy_manipulator {
  meta:
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
  strings:
    $n_networksetup = "networksetup"
    $n_setwebproxy = "-setwebproxy"
    $n_setsecurewebproxy = "-setsecurewebproxy"
	$not_networksetup = "networksetup tool"
  condition:
    2 of ($n_*) and none of ($not*)
}
