rule exclamations: medium {
  meta:
    description = "gets very excited"

  strings:
    $exclaim = /[\w ]{2,32} [\w ]{2,32}\!{2,16}/

    $not_bug = "DYNAMIC LINKER BUG!!!"

  condition:
    // glibc's own "DYNAMIC LINKER BUG!!!" string is itself an $exclaim match, so a
    // plain none-of guard exempts every statically glibc-linked binary. Require an
    // $exclaim match that starts outside every copy of that string instead.
    $exclaim and (#not_bug == 0 or for any i in (1..#exclaim): (
        for all j in (1..#not_bug): (
          @exclaim[i] < @not_bug[j] or @exclaim[i] >= @not_bug[j] + !not_bug[j]
        )
      ))
}
