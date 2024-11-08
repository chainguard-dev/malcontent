rule libgcj_so: override {
  meta:
    description               = "libgcj.so"
    malware_CobaltStrike_v3v4 = "medium"

  strings:
    $copyright1 = "# Copyright (C) 1991-2005 Unicode, Inc."
    $copyright2 = "# Copyright (C) 2004  Free Software Foundation, Inc."
    $copyright3 = "# Copyright (C) 2005  Free Software Foundation, Inc."
    $copyright4 = "# Copyright (C) 2006, 2010  Free Software Foundation, Inc."
    $java_lang  = /_\w{0,32}_java_lang_\w{0,32}/
    $zn         = /_(ZN3|ZN4|ZN5)java\w{0,128}/

  condition:
    filesize <= 64MB and all of ($copyright*) and #java_lang > 1024 and #zn > 64000
}
