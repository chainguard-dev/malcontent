
rule github_raw_usercontent : notable {
  meta:
    description = "References raw.githubusercontent.com"
  strings:
    $raw_github = "raw.githubusercontent.com"
    $not_node = "NODE_DEBUG_NATIVE"
  condition:
    $raw_github and $not_node
}

rule github_raw_user : notable {
  strings:
    $github = "github.com"
    $raw_master = "raw/master"
    $raw_main = "raw/main"
    $not_node = "NODE_DEBUG_NATIVE"
  condition:
    $github and any of ($raw*) and none of ($not*)
}
