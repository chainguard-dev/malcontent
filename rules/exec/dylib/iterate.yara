rule dl_iterate_phdr {
  meta:
    description = "iterate over list of shared objects"
    ref         = "https://man7.org/linux/man-pages/man3/dl_iterate_phdr.3.html"

  strings:
    $dlopen = "dl_iterate_phdr" fullword

  condition:
    any of them
}

