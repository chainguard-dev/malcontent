rule github_raw_usercontent: medium {
  meta:
    description = "References raw.githubusercontent.com"

  strings:
    $raw_github = "raw.githubusercontent.com"
    $not_node   = "NODE_DEBUG_NATIVE"

  condition:
    $raw_github and $not_node
}

rule github_raw_user: medium {
  meta:

    hash_2023_spirit          = "26ba215bcd5d8a9003a904b0eac7dc10054dba7bea9a708668a5f6106fd73ced"

  strings:
    $github     = "github.com"
    $raw_master = "raw/master"
    $raw_main   = "raw/main"
    $not_node   = "NODE_DEBUG_NATIVE"

  condition:
    $github and any of ($raw*) and none of ($not*)
}
