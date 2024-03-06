
rule unlink {
	meta:
		pledge = "wpath"
		syscall = "unlink"
		description = "deletes files"
	strings:
		$unlink = "unlink" fullword
		$unlinkat = "unlinkat" fullword
	condition:
		any of them
}


rule rm_f_hardcoded_tmp_path : suspicious {
  meta:
    hash_2023_Backdoors_Backdoor_Linux = "0e08cfb2d92b67ad67e7014e2e91849be3ef1b13c201b7ae928a1bab5a010b5b"
    hash_2023_Backdoors_Backdoor_Linux_Rootin = "4a6a9aa068fb133bd6ef06e95a65bfadcb5b52d0281caed6ff727b9a8fa293ec"
    hash_2023_Backdoors_Backdoor_Linux_Rootin = "cc6672b5825e0a5db7fd4ff8134a02653d3b432236e73f23898a10f09242e158"
    hash_2023_Linux_Linux_RedMenshenBPFDoor = "228746e67078354963f2c119ca62e2cfec4e0f4daf208c9d18713f581be9ad62"
    hash_2023_Mirai_Family_Mirai_Linux_Eragon2_0 = "fb443019a5206c4e4afac7cd6ec83ca3547db61e8931fd0e58f4aaf28dd6381e"
    hash_2023_Mirai_Family_Mirai_Linux_yakuza = "c8175e88ccf35532184c42506c99dde75d582e276fa7c2fd46dccbf7e640e278"
    hash_2023_Perl_Backdoor_Perl_Dompu = "f17b6917b835603ef24ab6926d938cbdefbfb537d43fa11965f2e2fdaf80faf6"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
  strings:
    $ref = /rm +\-[a-zA-Z]{,1}f[a-zA-Z]{,1} \/(tmp|var|dev)\/[\w\/\.\-\%]{0,64}/
	$not_apt = "/var/lib/apt/lists"
  condition:
	$ref and none of ($not*)
}
