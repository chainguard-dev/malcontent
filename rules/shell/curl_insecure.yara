rule curl_insecure : suspicious {
	meta:
		description = "Invokes curl in insecure mode"
	strings:
		$ref = /curl [\w\- ]{0,4}-k/
	condition:
		any of them
}
