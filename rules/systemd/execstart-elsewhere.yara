
rule execstart_danger_path_val : suspicious {
  meta:
    ref = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    description = "Starts from a dangerous-looking path"
  strings:
    $awkward = /ExecStart=\/(boot|var|tmp|dev|root)\/[\.\w\-\/]{0,32}/
  condition:
    filesize < 4096 and any of them
}

rule execstart_unexpected_dir_val : notable {
  meta:
    description = "Starts from an unusual path"
    ref = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    hash_2023_Downloads_kinsing = "05d02411668f4ebd576a24ac61cc84e617bdb66aa819581daa670c65f1a876f0"
    hash_2023_articles_https_pberba_github_io_security_2022_02_07_linux_threat_hunting_for_persistence_systemd_generators = "8c227f67a16162ffd5b453a478ced2950eba4cbe3b004c5cc935fb9551dc2289"
    hash_2024_2024_Spinning_YARN_yarn_fragments = "723326f8551f2a92ccceeec93859f58df380a3212e7510bc64181f2a0743231c"
  strings:
    $execstart = /ExecStart=\/[\w\/]{1,128}/
    $expected_bin = "ExecStart=/bin"
    $expected_etc_rc = "ExecStart=/etc/rc"
    $expected_etc_update = "ExecStart=/etc/update"
    $expected_lib = "ExecStart=/run"
    $expected_lib_ufw = "ExecStart=/lib/"
    $expected_nix = "ExecStart=/nix"
    $expected_sbin = "ExecStart=/sbin"
    $expected_usr = "ExecStart=/usr"
  condition:
    filesize < 102400 and $execstart and none of ($expected_*)
}
