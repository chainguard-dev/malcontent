rule eval {
	strings:
		$eval = /eval\(.{0,64}base64_decode/
	condition:
		any of them
}

