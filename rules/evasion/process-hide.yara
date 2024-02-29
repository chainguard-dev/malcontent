
rule elf_processhide : suspicious {
	meta:
		description = "userland rootkit designed to hide processes"
	strings:
		$prochide = "processhide"
		$process_to_filter = "process_to_filter"
	condition:
		uint32(0) == 1179403647 and all of them
}

rule elf_possible_prochid : suspicious {
  meta:
    ref = "prochid.c"
  strings:
    $proc_self_fd = "/proc/self/fd/%d"
    $proc_stat = "/proc/%s/stat"
    $readdir = "readdir"
  condition:
    uint32(0) == 1179403647 and all of them
}


rule process_hider {
  meta:
    hash_2014_MacOS_logind = "65c89525ea4da91500c021e5ac3cb67cf2c29086cca3ef7c75a44ac38cc1cce5"
    hash_2023_FontOnLake_1F52DB8E3FC3040C017928F5FFD99D9FA4757BF8_elf = "efbd281cebd62c70e6f5f1910051584da244e56e2a3228673e216f83bdddf0aa"
    hash_2023_FontOnLake_27E868C0505144F0708170DF701D7C1AE8E1FAEA_elf = "d7ad1bff4c0e6d094af27b4d892b3398b48eab96b64a8f8a2392e26658c63f30"
    hash_2023_FontOnLake_45E94ABEDAD8C0044A43FF6D72A5C44C6ABD9378_elf = "f60c1214b5091e6e4e5e7db0c16bf18a062d096c6d69fe1eb3cbd4c50c3a3ed6"
    hash_2023_FontOnLake_49D4E5FCD3A3018A88F329AE47EF4C87C6A2D27A_elf = "95f37c26707a9ef03f1a94cb0349484053c7ae9791352851d22a6ecdb018da71"
    hash_2023_FontOnLake_56580E7BA6BF26D878C538985A6DC62CA094CD04_elf = "2daa5503b7f068ac471330869ccfb1ae617538fecaea69fd6c488d57929f8279"
    hash_2023_FontOnLake_771340752985DD8E84CF3843C9843EF7A76A39E7_elf = "602c435834d796943b1e547316c18a9a64c68f032985e7a5a763339d82598915"
    hash_2023_FontOnLake_B439A503D68AD7164E0F32B03243A593312040F8_elf = "10c7e04d12647107e7abf29ae612c1d0e76a79447e03393fa8a44f8a164b723d"
  strings:
    $hide_process = "hide_proc"
    $proc_hide = "proc_hide"
    $process_hide = "process_hide"
    $process_hiding = "process_hiding"
  condition:
    any of them
}
