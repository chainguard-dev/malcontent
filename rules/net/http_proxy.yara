rule proxy_auth {
	meta:
		description = "Able to use an HTTP proxy that requires authentication"
	strings:
		$ref = "Proxy-Authorization"
	condition:
		any of them
}

rule proxy_pac {
	meta:
		description = "Able to find proxies via a PAC file"
	strings:
		$ref = "PACFile" fullword
	condition:
		any of them
}

rule http_proxy_env {
	meta:
		description = "Able to find HTTP proxies"
	strings:
		$ref = "HTTP_PROXY"
		$ref2 = "HTTPS_PROXY"
	condition:
		any of them
}
