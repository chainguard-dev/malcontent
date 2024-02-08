rule http_request {
	strings:
		$gRPC = "gRPC" fullword
	condition:
		any of them
}
