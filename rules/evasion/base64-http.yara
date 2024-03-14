rule base64_http_val : suspicious {
    meta:
        description = "base64 HTTP protocol references"
    strings:
		$user_agent = "User-Agent" base64
		$mozilla_slash = "Mozilla/" base64
		$referer = "Referer" base64
		$http_1x = "HTTP/1." base64
    condition:
        any of them
}
