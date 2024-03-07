rule activity_monitor_checker : suspicious {
  meta:
    hash_2020_BirdMiner_tonsillith = "9f8dba1cea7c8a4d7701a6a3e2d826202ba7e00e30e9c836c734ad6842b8cb5e"
    hash_2020_BirdMiner_tormina = "4179cdef4de0eef44039e9d03d42b3aeca06df533be74fc65f5235b21c9f0fb1"
  strings:
	$ps = "ps" fullword
	$pgrep = "pgrep" fullword
	$am = "Activity Monitor" fullword
  condition:
	$am and any of ($p*)
}
