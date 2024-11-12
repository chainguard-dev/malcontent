rule linux_test_script: override linux {
  meta:
    semicolon_short_tmp          = "medium"
    bash_dev_tcp                 = "medium"
    relative_background_launcher = "medium"
    chattr_immutable_caller_high = "medium"
    hidden_short_path            = "medium"
    kernel_module_loader         = "medium"
    cd_root                      = "medium"
    dmesg_clear                  = "medium"
    description                  = "Linux test script"

  strings:
    $gpl  = "# SPDX-License-Identifier: GPL-2.0"
    $bash = "#!/bin/bash"
    $sh   = "#!/bin/sh"

  condition:
    filesize < 32KB and $gpl in (1..256) and ($bash in (0..8) or $sh in (0..8))
}
