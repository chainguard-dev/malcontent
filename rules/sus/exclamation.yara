rule exclamations: medium {
  meta:
    description = "gets very excited"

  strings:
    $exclaim = /[\w ]{2,32} [\w ]{2,32}\!{2,16}/

    $not_bug = "DYNAMIC LINKER BUG!!!"

  condition:
    $exclaim and none of ($not*)
}
