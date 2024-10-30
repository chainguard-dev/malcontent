rule context_init: override {
  meta:
    description      = "context/__init__.py"
    py_dropper_chmod = "medium"

  strings:
    $comment = "# change the file to be readable,writable,executable: 0777"

  condition:
    all of them
}
