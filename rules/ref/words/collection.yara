

rule collect_data : notable {
  meta:
	description = "Uses terms that reference data collection"
  strings:
    $ref = "collect_data"
    $ref2 = "CollectData"
	$ref3 = "DataCollection"
  condition:
	any of them
}
