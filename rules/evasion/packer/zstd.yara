import "math"

rule custom_zstd : suspicious {
    meta:
        description = "contains and extracts packed ZStandard content"
		ref = "https://github.com/facebook/zstd"
    strings:
		// Thanks to https://github.com/VaccinatorSec/yara-rules/blob/master/rules/compressed.yar
		$ref = {28 B5 2F FD}
		$ref2 = "ZSTD_decompressStream"
    condition:
		// matches elf or macho
	    filesize < 64MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and $ref and $ref2 and math.entropy(1200,filesize) > 7
}

