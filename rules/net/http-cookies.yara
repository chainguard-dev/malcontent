rule http_cookie : notable {
	meta:
		pledge = "inet"
		description = "Able to access HTTP resources using cookies"
		ref = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"
	strings:
		$Cookie = "Cookie"
		$HTTP = "HTTP"

		$http_cookie = "http_cookie"
		$http_cookie2 = "HTTP_COOKIE"
	condition:
		any of ($http_cookie*) or ($Cookie and $HTTP)
}
