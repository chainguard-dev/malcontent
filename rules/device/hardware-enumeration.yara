
rule linux_dmidecode_hardware_profiler : suspicious {
  strings:
    $p_dmidecode = "dmidecode"
    $not_osquery = "OSQUERY_WORKER"
    $not_hasbangbash = "#!/bin/bash"
    $not_compdef = "#compdef"
  condition:
    filesize < 157286400 and any of ($p_*) and none of ($not_*)
}
