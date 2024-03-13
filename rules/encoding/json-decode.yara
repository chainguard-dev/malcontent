

// harmless because all binaries include it
rule jsondecode {
	strings:
		$jsond = "JSONDecode"
		$ju = "json.Unmarshal"
		$jp = "JSON.parse"
	condition:
		any of them
}



// harmless because all Go binaries include it
rule unmarshal_json : harmless {
	strings:
		$unmarshal = "UnmarshalJSON"
	condition:
		any of them
}
