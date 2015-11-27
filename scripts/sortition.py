# sortition.py for Psyrcd.
# Implements channel mode +sortition
# https://en.wikipedia.org/wiki/Sortition
#
# This channel mode de-ops active channel operators and selects a random 1/4 of
# the channel to be operators every n minutes.
#
# Luke Brooks, 2015
# MIT License

# Colour key:
# \x02 bold
# \x03 coloured text
# \x1D italic text
# \x0F colour reset
# \x16 reverse colour
# \x1F underlined text

import time
import random
MODE_NAME  = "sortition"
SRV_DOMAIN = cache['config']['SRV_DOMAIN']

def smsg(channel, msg):
    for client in channel.clients:
        break
    client.broadcast(channel.name, ':%s NOTICE %s :%s\n' % \
        (SRV_DOMAIN, channel.name, msg)) 

if 'init' in dir():
    provides = "cmode:%s:Implements administrative sortition." % MODE_NAME

if 'display' in dir():
    # The structure in channel.modes is a list where
    # the zeroth element is the duration between changes, in minutes
    # and the first element is the timestamp of the previous change.
    p      = channe.modes[MODE_NAME][1]
    output = "(Next selection in %i minutes.)"

if 'set' in dir():
    if set:
        if not args:
            message = "Please specify a duration in minutes. Eg: +sortition:20"
            client.broadcast(client.nick, ':%s NOTICE %s :%s\n' % \
                (SRV_DOMAIN, client.nick, message))
            cancel = True
        else:
            channel.modes[MODE_NAME] = [int(args[0]),0]
    else:
        del channel.modes[MODE_NAME]

if 'func' in dir():
    duration = int(channel.modes[MODE_NAME][0]) * 60
    then     = channel.modes[MODE_NAME][1]
    now      = int(time.time())
    if (now-then) >= duration:
        channel.modes[MODE_NAME][1] = now
        # Select a new administration
        count = len(channel.clients)
        count = count / 4
        
        if count == 0: count += 1

        administration = random.sample(channel.clients, count)

        # Grab a client object to broadcast de-op messages with
        for client in channel.clients: break

        # Remove existing channel operators
        for o in channel.ops:
            for n in o:
                client.broadcast(channel.name, ':%s MODE %s: -qaohv %s' % (SRV_DOMAIN, channel.name, n))
            del o[:]

        # Instate the new administration
        for mode in ['q', 'a', 'o', 'h']:
            if mode in channel.supported_modes and mode in channel.modes:
                for c in administration:
                    channel.modes[mode].append(c.nick)
                    c.broadcast(channel.name, ':%s MODE %s: +%s %s' % \
                        (SRV_DOMAIN, channel.name, mode, c.nick))
                break
