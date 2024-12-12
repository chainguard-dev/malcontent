rule minecraft_feather: high {
  meta:
    description = "accesses Minecraft credentials (Feather)"

  strings:
    $ = ".feather"
    $ = "accounts.json"

  condition:
    all of them
}
