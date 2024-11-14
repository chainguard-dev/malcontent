rule dscl_caller: medium {
  meta:
    description       = "Calls dscl (Directory Service command line utility)"
    hash_2018_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"

  strings:
    $dscl_local     = /dscl +\. +-\w{1,128}/
    $dsenableroot   = "dsenableroot"
    $not_read_users = "dscl . -read /Users/"

  condition:
    filesize < 131072 and any of ($d*) and none of ($not*)
}
