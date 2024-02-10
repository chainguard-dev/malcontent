rule php_eval {
	meta:
		description = "evaluate code dynamically using eval"
	strings:
		$php = "<?php"
		$eval = "eval("
	condition:
		all of them
}
