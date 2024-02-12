
rule b64 {
	meta:
		description = "Supports base64 encoded strings"
	strings:
		$base64 = "base64"
	condition:
		any of them
}
