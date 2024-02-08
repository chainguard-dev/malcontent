
rule go {
	strings:
		$gocsv = "gocsv."
		$unmarshal = "UnmarshalCSV"
	condition:
		any of them
}
