if 'init' in dir(): provides="command:disect:Divulges information on channel and user objects."
else:
  if not client.oper: client.broadcast(client.nick, ': IRCops Only.')
  else:
    if params:
      if params.startswith('#'):
        channel = client.server.channels.get(params)
        if channel:
          message = 'Channel %s: %s\n' % (channel.name, repr(channel))
          if channel.topic:
            message+= 'Topic: %s\n' % channel.topic
          message+= 'Clients: %s\n' % str(channel.clients)
          message+= 'Supported modes:\n'
          for m,d in channel.supported_modes.items():
            message += "  %s    %s\n" % (m,d)
          message+= 'Active mode(s): %s\n' % str(channel.modes)
          for line in message.split('\n'):
            client.broadcast(client.nick, ': %s' % line)
      else:
        c = client.server.clients.get(params)
        if c:
          message = 'Client %s: %s\n' % (c.nick, repr(c))
          if c.vhost:
              message += 'Vhost: %s\n' % c.vhost
          if c.user:
              message += 'User: %s\n' % c.user
          if c.host:
              message += 'host: %s\n' % str(c.host)
          message+= 'Channels: %s\n' % str(c.channels)
          message+= 'Supported modes:\n'
          for m,d in c.supported_modes.items():
            message += "  %s    %s\n" % (m,d)
          message+= 'Active mode(s): %s\n' % str(c.modes)
          for line in message.split('\n'):
            client.broadcast(client.nick, ': %s' % line)
    else:
      client.broadcast(client.nick, ':%s' % client.server.channels)
      client.broadcast(client.nick, ':%s' % client.server.clients)

