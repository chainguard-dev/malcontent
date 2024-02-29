
rule sysctl_machdep {
	meta:
		description = "gets detailed hardware information using sysctl"
	strings:
		$ref = "kern.osproductversion"
		$ref2 = "machdep.cpu.vendor"
		$ref3 = "machdep.cpu.brand_string"
		$ref4 = "hw.cpufrequency"
	condition:
		2 of them
}

rule macos_hardware_profiler : notable {
  meta:
	description = "Gathers hardware information"
    hash_2023_DDosia_d_mac_arm64 = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2023_amos_stealer_a = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2019_Macma_CDDS_at = "341bc86bc9b76ac69dca0a48a328fd37d74c96c2e37210304cfa66ccdbe72b27"
    hash_2020_FinSpy_installer = "80d6e71c54fb3d4a904637e4d56e108a8255036cbb4760493b142889e47b951f"
    hash_2017_FlashBack = "8d56d09650ebc019209a788b2d2be7c7c8b865780eee53856bafceffaf71502c"
    hash_2021_objective_see_Malware_MapperState = "919d049d5490adaaed70169ddd0537bfa2018a572e93b19801cf245f7fd28408"
    hash_2023_RustBucket_Stage_3 = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
    hash_2021_miner_igtpi = "43fab92516cdfaa88945996988b7cfe987f26050516503fb2be65592379d7d7f"
    hash_2021_miner_malxmr_ccibl = "ac6818140883e0f8bf5cef9b5f965861ff64cebfe181ff025e1f0aee9c72506c"
    hash_2021_miner_qcvsu = "edff1edfc410a5f4509d09c1264ce53236096f89231d415edbe6326e4e8d3fa3"
  strings:
    $p_system_profiler = "system_profiler SPHardwareDataType"
    $p_uuid = "IOPlatformUUID"
    $p_ioreg = "ioreg -"
    $p_hw_model = "hw.model"
    $p_machineid = "machineid.ID"
    $p_machineid_github = "github.com/denisbrodbeck/machineid"
  condition:
    filesize < 157286400 and any of ($p_*)
}
