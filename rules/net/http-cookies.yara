rule http_cookie : notable {
	meta:
		pledge = "inet"
		description = "Able to access HTTP resources using cookies"
	strings:
		$Cookie = "Cookie"
		$HTTP = "HTTP"
	condition:
		all of them
}
