rule ignore_f_string {
	meta:
		description = "detect f-string usage and ignore"
	strings:
		$fstring_single = /f'\s*\w{1,32}/
		$fstring_double = /f"\s*\w{1,32}/
		$fstring_triple_single = /f'''\s*\w{1,32}/
		$fstring_triple_double = /f"""\s*\w{1,32}/
	condition:
		none of them
}

rule ignore_comment {
	meta:
		description = "detect comments up to PEP8's limit and ignore"
	strings:
		$comment = /\s*#[^\n]{0,79}/
	condition:
		none of them
}
