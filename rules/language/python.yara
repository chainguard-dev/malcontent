rule dangerous_fstring : notable {
	meta:
		description = "detects dangerous f-strings that can be used for code execution"
    strings:
		$f_string = /f'[^']*?{.*?(__import__|os\.system|os\.popen|subprocess|eval|exec|open).*?}/
		$f_string_double = /f"[^"]*?{.*?(__import__|os\.system|os\.popen|subprocess|eval|exec|open).*?}/
		$f_string_triple = /f'''[^''']*?{.*?(__import__|os\.system|os\.popen|subprocess|eval|exec|open).*?}/
		$f_string_triple_double = /f"""[^"""]*?{.*?(__import__|os\.system|os\.popen|subprocess|eval|exec|open).*?}/
    condition:
        any of ($f_string*)
}

rule ignore_comment {
	meta:
		description = "detect comments up to PEP8's limit and ignore"
	strings:
		$comment = /\s*#[^\n]{0,79}/
	condition:
		none of them
}
