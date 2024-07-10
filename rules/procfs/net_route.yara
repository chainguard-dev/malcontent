rule proc_net_route : medium {
  meta:
    description = "gets network route information"
    hash_2023_Unix_Dropper_Mirai_1703 = "1703bd27e0ae38a53e897b82554f95eaa5a88f2b0a6c2c9d973d7e34d05b2539"
    hash_2023_Unix_Dropper_Mirai_1b29 = "1b29269a4ef50ee56a473eb515732a118d67fe6efa27fd21c057b6fd4ccc501b"
    hash_2023_Unix_Dropper_Mirai_1ba6 = "1ba6b973e571bf63bca52c366c3ddb0046511831c533acff280d2047474cd739"
  strings:
    $ref = "/proc/net/route"
  condition:
    any of them
}


rule proc_net_route_high : high {
  meta:
    description = "gets network route information"
    hash_2023_Unix_Dropper_Mirai_1703 = "1703bd27e0ae38a53e897b82554f95eaa5a88f2b0a6c2c9d973d7e34d05b2539"
    hash_2023_Unix_Dropper_Mirai_1b29 = "1b29269a4ef50ee56a473eb515732a118d67fe6efa27fd21c057b6fd4ccc501b"
    hash_2023_Unix_Dropper_Mirai_1ba6 = "1ba6b973e571bf63bca52c366c3ddb0046511831c533acff280d2047474cd739"
  strings:
    $ref = "/proc/net/route"
	$not_usage = "Usage: route"
	$not_host_route = "host route"
	$not_route_addr = "route address"
  condition:
    filesize < 1MB and $ref and none of ($not*)
}
