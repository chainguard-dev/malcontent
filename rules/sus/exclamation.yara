import "math"

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
    //
    // Comparing occurrence counts (#exclaim > #not_bug) cannot replace this test:
    // $exclaim begins with a variable-width class, so a single copy of the glibc
    // string yields one match per start offset inside it. The count comparison then
    // succeeds on exactly the statically-linked binaries this guard exists to
    // exempt -- measured over the sample corpus, it re-fires on all six files that
    // contain the string, two of which are clean.
    //
    // The iteration limits keep the cost bounded on input holding many copies of the
    // string. Both sit far above the number of matches one copy can produce, so they
    // never truncate a realistic search.
    $exclaim and (#not_bug == 0 or for any i in (1..math.min(#exclaim, 256)): (
        for all j in (1..math.min(#not_bug, 16)): (
          @exclaim[i] < @not_bug[j] or @exclaim[i] >= @not_bug[j] + !not_bug[j]
        )
      ))
}
