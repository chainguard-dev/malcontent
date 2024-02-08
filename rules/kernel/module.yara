rule lkm {
	strings:
		$vergmagic = "vermagic="
		$srcversion = "srcversion="
	condition:
		all of them
}
