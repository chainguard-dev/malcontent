
rule executable_calls_archive_tool : suspicious {
  meta:
	description = "command shells out to tar"
  strings:
    $a_tar_c = "tar -c"
    $a_tar_rX = "tar -r -X"
    $a_tar_T = "tar -T"
    $hash_bang = "#!"
  condition:
    any of ($a*) and not $hash_bang in (0..2)
}