import "math"

rule high_entropy_elf : suspicious {
  meta:
	description = "Obfuscated ELF binary content"
  condition:
    uint32(0) == 1179403647 and math.entropy(1200,6000) > 7
}
