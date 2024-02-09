rule eval_base64 {
	strings:
		$eval = /eval\(.{0,64}base64/
	condition:
		any of them
}

