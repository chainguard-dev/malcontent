rule fake_kworker_val : critical linux {
  meta:
    description = "Pretends to be a kworker kernel thread"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
  strings:
    $kworker = /\[{0,1}kworker\/[\d:\]]{1,5}/
    $kworker3 = "[kworker"
  condition:
    filesize < 1MB and any of ($k*)
}

rule kworker : medium linux {
  meta:
    description = "Mentions kworker"
  strings:
    $kworker2 = "kworker" fullword
	$not_under_kworker = "_kworker"
  condition:
    filesize < 1MB and any of ($k*) and none of ($not*)
}

rule fake_syslogd : critical {
  meta:
    description = "Pretends to be syslogd"
  strings:
    $ref = "[syslogd]"
  condition:
    filesize < 1MB and any of them
}

rule fake_bash : high {
  meta:
    description = "Pretends to be a bash process"
  strings:
    $bash = "-bash" fullword
  condition:
	filesize < 8KB and $bash
}

rule fake_systemd : critical linux {
  meta:
    description = "Pretends to be a systemd worker"
  strings:
    $ref = "systemd-worker" fullword
  condition:
	filesize < 10MB and $ref
}

rule fake_process_names : high {
	meta:
		description = "mentions known fake process name"
	strings:
		$kdevchecker = "kdevchecker" fullword
		$kworkerr = "kworkerr" fullword
		$ksoftriqd = "ksoftriqd" fullword
		$kdevtmpfsi = "kdevtmpfsi" fullword
		$kthreaddk = "kthreaddk" fullword
		$deamon = "deamon" fullword
	condition:
		filesize < 10MB and any of them
}
