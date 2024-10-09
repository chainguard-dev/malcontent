rule context_init : override {
  meta:
    description = "context/__init__.py"
    py_dropper_chmod = "medium"
  strings:
    $chmod = "os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)"
    $comment1 = "Add support for removing read-only files on Windows."
    $comment2 = "# change the file to be readable,writable,executable: 0777"
  condition:
    all of them
}
