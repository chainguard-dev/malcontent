rule php_hidden_eval : high {
	meta:
		description = "Appears to hide and evaluate a function"
	strings:
		$m_php = "php"
		$m_eval = /eval\(\$[a-z]{0,16}/
		$func = / {0,2}={0, 2}\"[_a-z]{4,16}\"/
	condition:
		all of them
}
