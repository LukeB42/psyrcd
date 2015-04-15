if 'init' in dir():
    provides = "command:cap:Simple response to IRCv3 capabilities requests."
elif "client" in dir() and client.nick:
    client.broadcast(
        client.nick,
        ": This server doesn't currently implement the IRC v3 capabilities model.")
