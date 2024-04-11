rule eval : suspicious {
	meta:
		description = "evaluate code dynamically using eval()"
	strings:
		$val = /eval\([a-z\"\'\(\,\)]{1,32}/ fullword
		$not_empty = "eval()"
	condition:
		$val and none of ($not*)
}

rule python_exec : suspicious {
	meta:
		description = "evaluate code dynamically using exec()"
	strings:
		$val = /exec\([a-z\"\'\(\,\)]{1,32}/ fullword
		$empty = "exec()"
	condition:
		$val and not $empty
}

rule shell_eval : suspicious {
	meta:
		description = "evaluate code dynamically using eval"	
	strings:
		$val = /eval \$\w{0,64}/ fullword
		// https://github.com/spf13/cobra/blob/0fc86c2ffd0326b6f6ed5fa36803d26993655c08/fish_completions.go#L59
		$not_fish_completion = "fish completion"
	condition:
		$val and none of ($not*)
}