
rule JSONDecode {
	strings:
		$jsond = "JSONDecode"
	condition:
		any of them
}


// harmless because all binaries include it
rule go : harmless {
	strings:
		$jsond = "JSONDecode"
		$unmarshal = "UnmarshalJSON"
		$ju = "json.Unmarshal"
	condition:
		any of them
}
