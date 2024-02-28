rule curl_insecure : suspicious {
	meta:
		description = "Invokes curl in insecure mode"
	strings:
		$ref = /curl [\w\- ]{0,4}-k [\-\w:\/]{0,64}/
	condition:
		$ref
}
