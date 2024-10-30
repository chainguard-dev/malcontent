rule magic_trace: override {
  meta:
    description      = "functorch/dim/magic_trace.py"
    py_dropper_chmod = "medium"

  strings:
    $facebook          = "# Copyright (c) Facebook, Inc. and its affiliates."
    $magic_trace       = "print(f\"Downloading magic_trace to: {magic_trace_cache}\")"
    $magic_trace_chmod = "subprocess.run([\"chmod\", \"+x\", magic_trace_cache])"

  condition:
    all of them
}
