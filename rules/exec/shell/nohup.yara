rule nohup_reference_value: medium {
  meta:
    description = "Runs command that is protected from termination"

  strings:
    $nohup        = "nohup" fullword
    $nohup_re_val = /nohup[ \%\{\}\$\-\w\"\']{2,64}/
    $not_usage    = "usage: nohup"
    $not_pushd    = "pushd"

    // Two fragments of the message coreutils/busybox nohup itself prints,
    // "ignoring input and appending output to 'nohup.out'". Malware legitimately
    // redirects to nohup.out, and "appending output" says nothing on its own, so
    // the pair is required as a set rather than member-by-member.
    $notgrp_coreutils_append   = "appending output"
    $notgrp_coreutils_out_file = "nohup.out"

  condition:
    filesize < 52428800 and any of ($nohup*) and none of ($not_*) and not all of ($notgrp_coreutils*)
}

rule elf_nohup: high {
  meta:
    description = "Runs command that is protected from termination"

  strings:
    $nohup        = "nohup" fullword
    $nohup_re_val = /nohup[ \%\{\}\$\-\w\"\']{2,64}/
    $not_usage    = "usage: nohup"
    $not_pushd    = "pushd"

    // See nohup_reference_value: the coreutils/busybox nohup message fragments
    // are required as a set, not member-by-member.
    $notgrp_coreutils_append   = "appending output"
    $notgrp_coreutils_out_file = "nohup.out"

  condition:
    uint32(0) == 1179403647 and filesize < 1MB and any of ($nohup*) and none of ($not_*) and not all of ($notgrp_coreutils*)
}

rule nohup_bash: high {
  meta:
    description = "Calls bash with nohup"

  strings:
    $ref = /nohup bash[ \w\/\&\.\-\%\\>]{0,32}/

  condition:
    any of them
}
