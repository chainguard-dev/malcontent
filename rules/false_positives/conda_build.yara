rule conda_load_setup_py_data: override {
  meta:
    setuptools_eval = "low"
    description     = "_load_setup_py_data.py"

  strings:
    $exec  = "exec(code, ns, ns)"
    $func  = "load_setup_py_data"
    $sbom1 = "# Copyright (C) 2014 Anaconda, Inc"
    $sbom2 = "# SPDX-License-Identifier: BSD-3-Clause"

  condition:
    filesize < 8KB and all of them
}
