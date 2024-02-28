
rule dynamic_hidden_path : notable {
	meta:
		description = "References a hidden file that can be generated dynamically"
		ref = "https://objective-see.org/blog/blog_0x73.html"
	strings:
		$ref = /%s\/\.[a-z][\w-]{0,32}/
		$config = "%s/.config"
	condition:
		$ref and not $config
}

rule static_hidden_path : suspicious {
	meta:
		description = "References hidden file path"
	strings:
		$ref = /\/[a-z]{3,10}[\w\/]{0,24}\/\.[\w\_\-\.]{0,16}/
	condition:
		$ref
}
