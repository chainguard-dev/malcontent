rule stickies: critical {
  meta:
    description = "steals the contents of macos Stickies application"

  strings:
    $note_group = "group.com.apple.notes"
    $note_other = "NoteStore.sqlite"
    $upload     = "upload"

  condition:
    all of them
}
