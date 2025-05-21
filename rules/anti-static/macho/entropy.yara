import "math"

include "rules/global/global.yara"

rule higher_entropy_6_9: medium {
  meta:
    description = "higher entropy binary (>6.9)"
    filetypes   = "macho"

  condition:
    global_small_macho and math.entropy(1, filesize) >= 6.9
}

rule high_entropy_7_2: high {
  meta:
    description = "high entropy binary (>7.2)"
    filetypes   = "macho"

  strings:
    // prevent bazel false positive
    $bin_java = "bin/java"

  condition:
    global_small_macho and math.entropy(1, filesize) >= 7.2 and not $bin_java
}
