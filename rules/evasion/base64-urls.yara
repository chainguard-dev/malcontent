
rule base64_url : suspicious {
	meta:
		description = "URL hidden in base64"
	strings:
		$http = "http:" base64
		$https = "https:" base64
		$ftp = "ftp:/" base64
		$tcp = "tcp:/" base64
		$user_agent = "User-Agent" base64
	condition:
		any of them
}
