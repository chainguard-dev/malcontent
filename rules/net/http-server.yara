rule http_server : notable {
	meta:
		pledge = "inet"
		description = "Able to serve HTTP requests"
	strings:
		$gin = "gin-gonic/"
		$gin_handler = "gin.HandlerFunc"
	condition:
		any of them
}
