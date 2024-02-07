
rule _close {
	strings:
		$_close = "_close"
	condition:
		any of them
}
