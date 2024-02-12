rule html : suspicious {
    meta:
        description = "Contains HTML content"
    strings:
		$ref = "<html>"
		$ref2 = "<img src>"
		$ref3 = "<a href>"
		$ref4 = "DOCTYPE html"
    condition:
        any of them
}