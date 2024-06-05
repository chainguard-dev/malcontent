rule base64_str_replace : critical {
	meta:
	   description = "creatively hidden forms of the term 'base64'"
	strings:
		$a = /\wba\ws\we64/
		$b = /\wb\wa\ws\we\w6\w4/
		$c = /\wb\wa\wse\w6\w4/
	condition:
		any of them
}