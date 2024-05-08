
rule systemd_not_in_dependency_tree : suspicious {
  meta:
    description = "Relies on nothing, nothing relies on it"
  strings:
    $execstart = "ExecStart="
    $expect_after = /After=\w/
    $expect_before = /Before=\w{1,128}/
    $expect_requires = /Requires=\w/
    $expect_condition = "ConditionPath"
    $expect_oneshot = "Type=oneshot"
    $expect_default = "DefaultDependencies=no"
    $expect_env = "EnvironmentFile="
    $expect_bus = "BusName="
    $expect_idle = "Type=idle"
    $expect_systemd = "ExecStart=systemd-"
  condition:
    filesize < 4096 and $execstart and none of ($expect_*)
}

rule type_forking_not_in_dep_tree : suspicious {
  meta:
    hash_2023_Txt_Malware_Sustes_0e77 = "0e77291955664d2c25d5bfe617cec12a388e5389f82dee5ae4fd5c5d1f1bdefe"
    hash_2023_Unix_Malware_Kaiji_3e68 = "3e68118ad46b9eb64063b259fca5f6682c5c2cb18fd9a4e7d97969226b2e6fb4"
    hash_2023_Unix_Malware_Kaiji_f4a6 = "f4a64ab3ffc0b4a94fd07a55565f24915b7a1aaec58454df5e47d8f8a2eec22a"
  strings:
    $forking = "Type=forking"
    $expect_after = /After=\w/
    $expect_before = /Before=\w{1,128}/
  condition:
    $forking and none of ($expect*)
}
