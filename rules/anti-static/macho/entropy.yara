import "math"

private rule smaller_macho {
  condition:
    filesize < 64MB and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

rule higher_entropy_6_9: medium {
  meta:
    description = "higher entropy binary (>6.9)"

  condition:
    smaller_macho and math.entropy(1, filesize) >= 6.9
}

rule high_entropy_7_2: high {
  meta:
    description = "high entropy binary (>7.2)"

  strings:
    // prevent bazel false positive
    $bin_java = "bin/java"

  condition:
    smaller_macho and math.entropy(1, filesize) >= 7.2 and not $bin_java
}
