rule php_eval {
	meta:
		description = "evaluate PHP code dynamically using eval"
	strings:
		$php = "<?php"
		$eval = "eval(" fullword
		$exec = "exec(" fullword
	condition:
		all of them
}


rule python_eval {
	meta:
		description = "evaluate Python dynamically using eval"
	strings:
		$python = "python"
		$eval = "eval(" fullword
		$exec = "exec(" fullword
	condition:
		$python and any of ($e*)
}
