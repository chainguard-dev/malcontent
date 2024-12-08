rule minecraft_meteor: high {
  meta:
    description = "accesses Minecraft credentials (Meteor)"

  strings:
    $ = ".meteor-client"
    $ = "accounts.nbt"

  condition:
    all of them
}
