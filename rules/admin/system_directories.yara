
rule system_fs_manipulator : notable {
  meta:
	description = "Modifies files within system directories"
    hash_2023_QubitStrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2021_Tsunami_Kaiten = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2021_gjif_tsunami_Gafygt = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
    hash_2023_OrBit_f161 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
    hash_2023_init_d_acpid = "b0cd9065704d205ea7087a0b2d4d6461305a2d12b03b8d2827e8e05e2013244d"
    hash_2023_init_d_auditd = "2617841f93faf85ba6d414bb79cce52fa69327d0546b10c9c1d99d8b7aee9db1"
    hash_2023_init_d_autofs = "3e006eafd6fe2af4d115a270fef161e3c9d470dd07205d08180edd13abafa88f"
    hash_2023_init_d_haldaemon = "cbf2a35e563d218d46153a50ab08545f033a14e1777f69e4edabea649710e05b"
  strings:
    $in_usr = /(mv|chattr|rm|touch) \/(bin|root|sbin|usr|var|lib|lib64|boot)\/[ \.\w\/]{0,64}/

	$not_mdm = "/var/db/MDM_EnableManagedApps"
  condition:
	$in_usr and none of ($not*)
}
