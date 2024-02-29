rule systemsetup_no_sleep : notable {
  meta:
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
  strings:
    $no_sleep = "systemsetup -setcomputersleep Never"
  condition:
    filesize < 10485760 and any of them
}
