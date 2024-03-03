rule etc_gshadow : notable {
  meta:
	description = "Accesses /etc/gshadow (group passwords)" 
  strings:
	$ref = "etc/gshadow"
  condition:
    any of them
}
