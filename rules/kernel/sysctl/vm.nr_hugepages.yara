
rule huge_pages : notable {
	meta:
		description = "accesses vm.nr_hugepages control"
	strings:
		$ref = "vm.nr_hugepages"
	condition:
		any of them
}