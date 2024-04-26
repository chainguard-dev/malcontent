rule dangerous_fstring : notable {
	meta:
		description = "detects dangerous f-strings that can be used for code execution"
    strings:
		$f_string = /f'[^']*?{.*?(__import__|os\.system|os\.popen|subprocess|eval|exec|open).*?}/
		$f_string_double = /f"[^"]*?{.*?(__import__|os\.system|os\.popen|subprocess|eval|exec|open).*?}/
		$f_string_triple = /f'''[^''']*?{.*?(__import__|os\.system|os\.popen|subprocess|eval|exec|open).*?}/
		$f_string_triple_double = /f"""[^"""]*?{.*?(__import__|os\.system|os\.popen|subprocess|eval|exec|open).*?}/
    condition:
        any of them
}

rule ignore_comment {
	meta:
		description = "detect comments up to PEP8's limit and ignore"
	strings:
		$comment = /\s*#[^\n]{0,79}/
	condition:
		none of them
}


rule eval : notable {
	meta:
		description = "evaluate code dynamically using eval()"
	strings:
		$val = /eval\([a-z\"\'\(\,\)]{1,32}/ fullword
		$not_empty = "eval()"
	condition:
		$val and none of ($not*) and dangerous_fstring
}

rule python_exec : notable {
	meta:
		description = "evaluate code dynamically using exec()"
	strings:
		$val = /exec\([a-z\"\'\(\,\)]{1,32}/ fullword
		$empty = "exec()"
	condition:
		$val and not $empty and dangerous_fstring
}

rule shell_eval : notable {
	meta:
		description = "evaluate shell code dynamically using eval"	
	strings:
		$val = /eval \$\w{0,64}/ fullword
		// https://github.com/spf13/cobra/blob/0fc86c2ffd0326b6f6ed5fa36803d26993655c08/fish_completions.go#L59
		$not_fish_completion = "fish completion"
	condition:
		$val and none of ($not*)
}
