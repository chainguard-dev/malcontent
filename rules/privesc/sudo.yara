rule sudo: medium {
  meta:
    description = "calls sudo"

  strings:
    $raw            = "sudo" fullword
    $cmd_val        = /sudo[ \'\"][ \/\,\.\w\%\$\-]{0,32}/ fullword
    $not_sudo_paths = "github.com/hashicorp/vault/api.sudoPaths"

  condition:
    $raw or $cmd_val and none of ($not*)
}
