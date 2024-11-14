rule proc_status: medium {
  meta:
    description = "access status fields for other processes"

    hash_2020_Dacls_SubMenu      = "846d8647d27a0d729df40b13a644f3bffdc95f6d0e600f2195c85628d59f1dc6"


  strings:
    $string = "/proc/%s/status" fullword
    $digit  = "/proc/%d/status" fullword
    $python = "/proc/{}/status" fullword

  condition:
    any of them
}
