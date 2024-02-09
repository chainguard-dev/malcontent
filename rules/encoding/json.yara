
rule encoding_json {
	strings:
		$jsone = "encoding/json"
	condition:
		any of them
}
