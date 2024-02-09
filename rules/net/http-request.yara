rule http_request {
	meta:
		pledge = "inet"
		description = "Makes HTTP (Hypertext Transport Protocol) requests"
	strings:
		$httpRequest = "httpRequest"
		$user_agent = "User-Agent"
		$http1 = "HTTP/1."
	condition:
		any of them
}
