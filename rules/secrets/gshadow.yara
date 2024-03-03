rule etc_gshadow : notable {
  meta:
	description = "accesses /etc/gshadow (group passwords)" 
  strings:
	$ref = "etc/gshadow"
  condition:
    any of them
}
