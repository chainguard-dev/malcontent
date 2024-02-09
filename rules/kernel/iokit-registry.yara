rule ref {
	meta:
		description = "Accesses the IOKit device driver registry"
	strings:
		$ref = "IORegistry"
	condition:
		any of them
}
