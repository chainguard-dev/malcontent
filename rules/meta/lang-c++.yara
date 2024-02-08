rule Z : harmless {
  strings:
	$zprefix = "__Z"
  condition:
	#zprefix > 5
}
