rule macOS_entitlements {
  meta:
  	description = "macOS entitlements"
  strings:
	$xml_key_val = /\<key\>com\.apple\.(private|security)\.[a-z\.]{0,63}\<\/key\>/
condition:
	any of them
}