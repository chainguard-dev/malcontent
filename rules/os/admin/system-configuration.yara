
rule systemsetup_no_sleep : medium {
  meta:
    hash_2018_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
  strings:
    $no_sleep = "systemsetup -setcomputersleep Never"
  condition:
    filesize < 10485760 and any of them
}
