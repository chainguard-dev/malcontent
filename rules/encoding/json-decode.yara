// harmless because all binaries include it
rule jsondecode {
	meta:
		description = "Decodes JSON messages"
	strings:
		$jsond = "JSONDecode"
		$ju = "json.Unmarshal"
		$jp = "JSON.parse"
	condition:
		any of them
}



// harmless because all Go binaries include it
rule unmarshal_json : harmless {
	meta:
		description = "Decodes JSON messages"
	strings:
		$unmarshal = "UnmarshalJSON"
	condition:
		any of them
}
