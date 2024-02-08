rule bsd {
	strings:
		$if_nametoindex = "if_nametoindex" fullword
		$if_indextoname = "if_indextoname" fullword
		$if_nameindex = "if_nameindex" fullword
		$if_freenameindex = "if_freenameindex" fullword
	condition:
		any of them
}

rule macos_scnetwork {
	strings:
		$ref = "SCNetworkServiceGet" fullword
	condition:
		any of them
}
