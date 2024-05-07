rule http_form_upload : notable {
	meta:
		pledge = "inet"
		description = "upload content via HTTP form"
	strings:
		$header = "application/x-www-form-urlencoded"
		$POST = "POST" fullword
	condition:
		all of them
}