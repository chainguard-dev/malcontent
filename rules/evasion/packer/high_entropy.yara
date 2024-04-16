import "math"

rule high_entropy_7 : suspicious {
    meta:
        description = "high entropy binary (>7.0)"
    condition:
		// matches elf or macho
	    filesize > 4096 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and math.entropy(1,filesize) > 7.0
}

rule high_entropy_75 : suspicious {
    meta:
        description = "high entropy binary (>7.5)"
    condition:
		// matches elf or macho
	    filesize > 4096 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and math.entropy(1,filesize) > 7.5
}

rule high_entropy_8 : suspicious {
    meta:
        description = "high entropy binary (>8) - likely packed"
    condition:
		// matches elf or macho
	    filesize > 4096 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and math.entropy(1,filesize) > 8.0
}


rule high_entropy_9 : suspicious {
    meta:
        description = "high entropy binary (>9.0)"
    condition:
		// matches elf or macho
	    filesize > 4096 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and math.entropy(1,filesize) > 9.0
}
