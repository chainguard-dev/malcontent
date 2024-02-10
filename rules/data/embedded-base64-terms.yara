rule contains_base64 : suspicious {
    meta:
        description = "Contains base64 content"
    strings:
		$file = "file" base64
		$directory = "directory" base64
		$address = "address" base64
		$html = "html" base64
		$uname = "uname" base64
		$select = "select" base64
		$company = "company" base64
		$cert = "cert" base64
    condition:
        any of them
}