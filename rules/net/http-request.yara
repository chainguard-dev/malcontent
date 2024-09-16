rule http_request {
	meta:
		pledge = "inet"
		description = "makes HTTP requests"
	strings:
		$httpRequest = "httpRequest"
		$user_agent = "User-Agent"
		$assemble = "httpAssemble"
		$connect = "httpConnect"
		$close = "httpClose"
		$http1 = "HTTP/1."
		$http2 = "Referer" fullword
		$uri = "open-uri" fullword
		$http_get = "http.get" fullword
	condition:
		any of them
}
