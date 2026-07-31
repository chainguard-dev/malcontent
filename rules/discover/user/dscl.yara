rule dscl_caller: medium {
  meta:
    description = "Calls dscl (Directory Service command line utility)"

  strings:
    $dscl_local     = /dscl +\. +-\w{1,128}/
    $dsenableroot   = "dsenableroot"
    $not_read_users = "dscl . -read /Users/"

  // $dscl_local also matches the benign "dscl . -read /Users/" spelling, so one
  // directory read used to suppress every other dscl invocation in the same
  // file. Compare occurrence counts instead of presence, and let
  // $dsenableroot stand on its own - a benign read says nothing about it.

  condition:
    filesize < 131072 and ($dsenableroot or ($dscl_local and #dscl_local > #not_read_users))
}
