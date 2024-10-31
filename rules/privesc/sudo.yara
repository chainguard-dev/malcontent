rule sudo: medium {
  meta:
    description                                                                          = "calls sudo"
    hash_2024_Downloads_4ba7 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_6e35                                                             = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929                                                             = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"

  strings:
    $raw            = "sudo" fullword
    $cmd_val        = /sudo[ \'\"][ \/\,\.\w\%\$\-]{0,32}/ fullword
    $not_sudo_paths = "github.com/hashicorp/vault/api.sudoPaths"

  condition:
    $raw or $cmd_val and none of ($not*)
}
