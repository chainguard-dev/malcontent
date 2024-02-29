rule trusted_cert_manipulator : suspicious {
  meta:
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
    hash_2017_AptorDoc_Dok_AppStore = "4131d4737fe8dfe66d407bfd0a0df18a4a77b89347471cc012da8efc93c661a5"
  strings:
    $security = "security"
    $add_trusted_cert = "add-trusted-cert"
	$not_certtool = "PROGRAM:certtool"
	$not_private = "/System/Library/PrivateFrameworks"
  condition:
	$security and $add_trusted_cert and none of ($not*)
}
