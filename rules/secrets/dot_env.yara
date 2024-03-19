rule dot_env_getter : suspicious {
	meta:
		description = "Requests /.env URLs via HTTP"
	strings:
		$ref = "GET /.env"
	condition:
		any of them
}
