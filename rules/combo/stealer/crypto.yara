rule js_crypto_stealer : high {
  meta:
    description = "possibly steals private cryptographic data"
  strings:
	$pk = "private_key"
	$pk2 = "PRIVATE_KEY"
	$pk3 = "privateKey"
	$pk4 = "privatekey"
	$pk5 = "fromSecretKey"

    $url = /https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/

	$POST = "POST"
	$not_webdav = "WebDAV certificate"
	$not_letsencrypt = "Letsencrypt"
	$not_letsencrypt2 = "letsencrypt"
  condition:
	filesize < 50KB and $url and $POST and any of ($pk*) and none of ($not*)
}
