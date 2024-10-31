

rule js_hex_obfuscation : critical {
	meta:
		description = "javascript function obfuscation (hex)"
	strings:
		$return = /return _{0,4}0x[\w]{0,32}\(_0x[\w]{0,32}/
		$const = /const _{0,4}0x[\w]{0,32}=[\w]{0,32}/
	condition:
		filesize < 1MB and any of them
}
