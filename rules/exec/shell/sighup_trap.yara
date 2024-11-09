rule trap_1: high {
  meta:
    description                          = "Protects itself from early termination via SIGHUP"
    hash_2023_Linux_Malware_Samples_3059 = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2023_Linux_Malware_Samples_553a = "553ac527d6a02a84c787fd529ea59ce1eb301ddfb180d89b9e62108d92894185"
    hash_2023_Linux_Malware_Samples_7a60 = "7a60c84fb34b2b3cd7eed3ecd6e4a0414f92136af656ed7d4460b8694f2357a7"

  strings:
    $ref  = "trap '' 1"
    $ref2 = "trap \"\" 1"
	$not_netcat_example = "ignore most signals; the parent will nuke the kid"
  condition:
    any of ($ref*) and none of ($not*)
}