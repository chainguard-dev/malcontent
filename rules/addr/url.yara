rule https_url {
  meta:
	description = "contains embedded HTTPS URLs"
  strings:
    $ref = /https:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
	$not_apple = "https://www.apple.com/appleca/"
  condition:
	$ref and none of ($not*)
}

rule http_url {
  meta:
	description = "contains embedded HTTP URLs"
  strings:
    $ref = /http:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
	$not_apple = "http://crl.apple.com/"
  condition:
	$ref and none of ($not*)
}

rule ftp_url {
  meta:
	description = "contains embedded FTP URLs"
  strings:
    $ref = /ftp:\/\/[\w][\w\.\/\-_]{8,64}/
  condition:
    any of them
}


rule ssh_url {
  meta:
	description = "contains embedded URLs"
  strings:
    $ref = /ssh:\/\/[\w][\w\.\/\-_]{8,64}/
  condition:
    any of them
}
