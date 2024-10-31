
rule system_fs_manipulator : medium {
  meta:
    description = "Modifies files within system directories"
    hash_2023_Linux_Malware_Samples_3059 = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2023_Linux_Malware_Samples_e212 = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
  strings:
    $in_usr = /(mv|chattr|rm|touch) \/(bin|root|sbin|usr|var|lib|lib64|boot)\/[ \.\w\/]{0,64}/
    $not_mdm = "/var/db/MDM_EnableManagedApps"
  condition:
    $in_usr and none of ($not*)
}
