rule php_eval : suspicious {
	meta:
		description = "evaluate PHP code dynamically using eval"
	strings:
		$php = "<?php"
		$eval = "eval(" fullword
	condition:
		$php and any of ($e*)
}


rule python_eval : suspicious {
	meta:
		description = "evaluate Python dynamically using eval"
	strings:
		$python = "python"
		$eval = "eval(" fullword
		$exec = "exec(" fullword
	condition:
		$python and any of ($e*)
}
