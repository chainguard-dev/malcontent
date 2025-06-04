rule arangodb_override: override {
  meta:
    R3C0NST_Shellcode_Apihashing_FIN8 = "low"

  strings:
    $ = "https://github.com/arangodb-helper/arangodb"
    $ = "/home/build/arangod"
    $ = "application/x-arango-dump"
    $ = "arangodb"

  condition:
    all of them
}
