rule http_post : notable {
	meta:
		pledge = "inet"
		description = "Able to submit content via HTTP POST"
	strings:
		$POST = "POST"
		$HTTP = "HTTP"
	condition:
		all of them
}
