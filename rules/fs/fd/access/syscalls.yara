rule _close : harmless {
	strings:
		$_close = "_close"
	condition:
		any of them
}
