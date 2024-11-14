rule huge_pages: medium {
  meta:
    description              = "accesses vm.nr_hugepages control"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"

  strings:
    $ref = "vm.nr_hugepages"

  condition:
    any of them
}
