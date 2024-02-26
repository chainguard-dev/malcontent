rule dirbuster : suspicious {
  strings:
	$ref = "dirbuster" fullword
  condition:
	$ref
}