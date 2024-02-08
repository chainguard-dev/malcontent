rule http_request {
	strings:
		$httpRequest = "httpRequest"
		$user_agent = "User-Agent"
		$http1 = "HTTP/1."
	condition:
		any of them
}
