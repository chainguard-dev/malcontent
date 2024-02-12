
rule dyntamic_hidden_path : suspicious {
	meta:
		description = "References a hidden file that can be generated dynamically"
		ref = "https://objective-see.org/blog/blog_0x73.html"
	strings:
		$ref = /%s\/\.[a-z][\w-]{0,32}/
	condition:
		any of them
}
