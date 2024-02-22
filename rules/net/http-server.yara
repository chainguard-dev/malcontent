rule http_server : notable {
	meta:
		pledge = "inet"
		description = "Able to serve HTTP requests"
	strings:
		$gin = "gin-gonic/"
	condition:
		any of them
}
