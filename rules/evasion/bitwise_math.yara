
rule excessive_bitwise_math : notable {
  meta:
	description = "excessive use of bitwise math"
  strings:
	$x = /\-{0,1}\d{1,8} \<\< \-{0,1}\d{1,8}/
condition:
   filesize < 128000 and #x > 10
}