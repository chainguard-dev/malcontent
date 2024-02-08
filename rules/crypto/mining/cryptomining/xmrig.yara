rule xmrig {
	strings:
		$ref = "XMRig"
	condition:
		any of them
}


