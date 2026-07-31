rule lkm_name: medium {
  meta:
    description = "mentions Linux kernel module by name"
    capability  = "CAP_SYS_MODULE"

  strings:
    $ko = /[a-z_]{2,12}\.ko/ fullword

    $o_kernel         = "kernel"
    $o_lsmod          = "lsmod"
    $o_rmmod          = "rmmod"
    $o_insmod         = "insmod"
    $o_modprobe       = "modprobe"
    $not_languages_ko = "languages.ko" fullword

  // $ko generalises "languages.ko", so one gcj locale token used to suppress
  // every other module name in the file. Compare occurrence counts instead of
  // presence; fullword on the suppressor keeps the two in step, so
  // "languages.kotlin" (which $ko cannot match) no longer counts.

  condition:
    $ko and any of ($o*) and #ko > #not_languages_ko
}
