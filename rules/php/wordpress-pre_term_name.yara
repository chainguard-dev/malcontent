rule refs {
	strings:
		$ref = "<pre_term_name("
	condition:
		any of them
}