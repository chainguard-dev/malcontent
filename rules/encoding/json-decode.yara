
rule JSONDecode {
	strings:
		$jsond = "JSONDecode"
		$unmarshal = "UnmarshalJSON" fullword
	condition:
		any of them
}


// harmless because all binaries include it
rule jsondecode : harmless {
	strings:
		$jsond = "JSONDecode"
		$unmarshal = "UnmarshalJSON"
		$ju = "json.Unmarshal"
		$jp = "JSON.parse"
	condition:
		any of them
}
