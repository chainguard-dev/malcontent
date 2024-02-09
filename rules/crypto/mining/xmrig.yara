rule xmrig {
	meta:
		description = "References XMRig, a high-performance cryptocurrency miner"
	strings:
		$ref = "XMRig"
	condition:
		any of them
}


