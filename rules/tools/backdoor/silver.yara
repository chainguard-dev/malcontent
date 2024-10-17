
rule c2_implant_sliver_proto : critical {
  meta:
    description = "Sliver C2 implant"
    hash_2023_Downloads_78eb = "78eb647f3d2aae5c52fcdc46ac1b27fb5a388ad39abbe614c0cfc902d223ccd6"
    hash_2023_Covid_softwareupdated = "d9bba1cfca6b1d20355ce08eda37d6d0bca8cb8141073b699000d05025510dcc"
  strings:
    $sliverpb = "sliverpb"
    $bishopfox = "bishopfox"
    $sliver_proto = "sliver.proto"
    $server_store_proto = "ServerStoreLprotobuf"
    $proc_name_proto = "ProcessNameKprotobuf"
  condition:
    filesize < 20971520 and 2 of them
}


rule c2_implant_sliver_obfuscated : high {
  meta:
    description = "Possible Sliver Linux implant"
	filetypes = "elf"
  strings:
	$coredump = ".CoreDump"
	$gvisor = "HasGvisorGSOCapability"
	$proxy_func = "ProxyFunc"
	$new_private = "NewPrivateKey"
	$optional_asn = "SkipOptionalASN1"
	$spoofing = "SetSpoofing"
	$append = "AppendCertsFromPEM"
	$decrypt = ".Decrypt"
  condition:
    filesize < 15MB and filesize > 10MB and uint32(0) == 1179403647 and all of them
}

rule c2_implant_sliver_functions : critical {
  meta:
    description = "Sliver C2 implant"
    hash_2023_Downloads_78eb = "78eb647f3d2aae5c52fcdc46ac1b27fb5a388ad39abbe614c0cfc902d223ccd6"
    hash_2023_Covid_softwareupdated = "d9bba1cfca6b1d20355ce08eda37d6d0bca8cb8141073b699000d05025510dcc"
  strings:
    $sliverpb = "GetImplantBuilds"
    $bishopfox = "GetBeaconJitter"
    $sliver_proto = "GetObfuscateSymbols"
    $server_store_proto = "GetBeaconID"
  condition:
    filesize < 20971520 and 2 of them
}

rule beaconjitter_xor : high {
  meta:
    description = "Sliver C2 implant"
    hash_2023_Downloads_78eb = "78eb647f3d2aae5c52fcdc46ac1b27fb5a388ad39abbe614c0cfc902d223ccd6"
    hash_2023_Covid_softwareupdated = "d9bba1cfca6b1d20355ce08eda37d6d0bca8cb8141073b699000d05025510dcc"
  strings:
    $ref = "BeaconJitter" xor
  condition:
    any of them
}
