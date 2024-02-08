rule eval {
	strings:
		$php = "<?php"
		$eval = "eval("
	condition:
		any of them
}