rule http_form : notable {
	meta:
		pledge = "inet"
		description = "upload content via HTTP form"
	strings:
		$ref = /Content-Type.{0,8}application\/x-www-form-urlencoded/
		$ref2 = "\"application/x-www-form-urlencoded"
		$ref3 = "'application/x-www-form-urlencoded"
	condition:
		any of them
}
