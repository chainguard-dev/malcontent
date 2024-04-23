import "math"

private rule smallBinary {
	condition:
		// matches ELF or machO binary
		filesize < 64MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

rule high_entropy_7_5 : notable {
    meta:
        description = "higher entropy binary (>7.5)"
    condition:
		smallBinary and math.entropy(1,filesize) >= 7.5
}

rule high_entropy_7_9 : suspicious {
    meta:
        description = "high entropy binary (>7.9)"
	strings:
		// prevent bazel false positive
		$bin_java = "bin/java"
    condition:
		smallBinary and math.entropy(1,filesize) >= 7.9 and not $bin_java
}
