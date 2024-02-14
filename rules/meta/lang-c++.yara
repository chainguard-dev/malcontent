rule Z : harmless {
  strings:
	$zprefix = "_Z"
  condition:
	#zprefix > 5
}

