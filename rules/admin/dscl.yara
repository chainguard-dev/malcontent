rule dscl_caller {
  meta:
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2012_getshell_siggen = "11fb341008357bd55cee77678d9ce9609e6faae411219878d3db09cb6c125167"
  strings:
    $dscl_local = /dscl +\. +-\w{1,128}/
    $dsenableroot = "dsenableroot"
    $not_read_users = "dscl . -read /Users/"
  condition:
    filesize < 131072 and any of ($d*) and none of ($not*)
}
