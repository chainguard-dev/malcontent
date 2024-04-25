rule http_server : notable {
	meta:
		pledge = "inet"
		description = "serves HTTP requests"
	strings:
		$gin = "gin-gonic/"
		$gin_handler = "gin.HandlerFunc"
	condition:
		any of them
}
