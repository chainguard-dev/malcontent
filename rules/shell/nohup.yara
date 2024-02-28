rule nohup_reference : notable {
  meta:
	description = "Runs command that is protected from termination"
    hash_2018_MacOS_CoinTicker = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
    hash_2019_Cointrazer = "138a54a0a1fe717cf0ffd63ef2a27d296456b5338aed8ef301ad0e90b0fe25ae"
    hash_2013_trojan_Janicab_python = "7684a74becf520141ff59dcfe5cbc391d5d710a67c2241bb75a05e9694156982"
    hash_2021_Tsunami_Kaiten = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2021_Tsunami_gjirtfg = "553ac527d6a02a84c787fd529ea59ce1eb301ddfb180d89b9e62108d92894185"
    hash_2021_Tsunami_Kaiten_ujrzc = "7a60c84fb34b2b3cd7eed3ecd6e4a0414f92136af656ed7d4460b8694f2357a7"
    hash_2021_gjif_tsunami_Gafygt = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
  strings:
    $nohup = "nohup" fullword
    $not_append = "appending output"
    $not_usage = "usage: nohup"
    $not_nohup_out = "nohup.out"
    $not_pushd = "pushd"
    $bin_sh = "#!/bin/sh"
    $bin_bash = "#!/bin/bash"
  condition:
    filesize < 52428800 and $nohup and none of ($not*) and not $bin_sh in (0..2) and not $bin_bash in (0..2)
}

rule elf_nohup : suspicious {
  meta:
	description = "Runs command that is protected from termination"
  strings:
    $nohup = "nohup" fullword
    $not_append = "appending output"
    $not_usage = "usage: nohup"
    $not_nohup_out = "nohup.out"
    $not_pushd = "pushd"
  condition:
	uint32(0) == 1179403647 and $nohup and none of ($not*)
}
