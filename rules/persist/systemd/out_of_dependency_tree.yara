rule systemd_not_in_dependency_tree: medium {
  meta:
    description = "Relies on nothing, nothing relies on it"

    filetypes = "service"

  strings:
    $execstart        = "ExecStart="
    $expect_after     = /After=\w/
    $expect_before    = /Before=\w{1,128}/
    $expect_requires  = /Requires=\w/
    $expect_condition = "ConditionPath"
    $expect_oneshot   = "Type=oneshot"
    $expect_default   = "DefaultDependencies=no"
    $expect_env       = "EnvironmentFile="
    $expect_bus       = "BusName="
    $expect_idle      = "Type=idle"
    $ex_systemd       = "ExecStart=systemd-"

  condition:
    // $execstart matches inside $ex_systemd, so a unit that launches one systemd- helper
    // was exempt no matter what else it launched; discount it by occurrence count. The
    // $expect_* strings are independent structural declarations and stay presence checks.
    filesize < 4096 and $execstart and #execstart > #ex_systemd and none of ($expect_*)
}

rule type_forking_not_in_dep_tree: high {
  meta:
    description = "forking service that nothing relies on"

  strings:
    $forking       = "Type=forking"
    $expect_after  = /After=\w/
    $expect_before = /Before=\w{1,128}/

  condition:
    filesize < 4096 and $forking and none of ($expect*)
}
