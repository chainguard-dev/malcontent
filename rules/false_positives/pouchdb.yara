rule pouchdb_override: override {
  meta:
    description                  = "pouchdb.min.js"
    unsigned_bitwise_math_excess = "medium"
    js_many_parseInt             = "medium"

  strings:
    $comment_1 = "// PouchDB 8.0.1"
    $comment_2 = "// "
    $comment_3 = "// (c) 2012-2023 Dale Harvey and the PouchDB team"
    $comment_4 = "// PouchDB may be freely distributed under the Apache license, version 2.0."
    $comment_5 = "// For all details and documentation:"
    $comment_6 = "// http://pouchdb.com"

  condition:
    all of them
}
