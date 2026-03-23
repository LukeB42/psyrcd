# sortition.py plugin for Psyrcd.
# Implements channel mode +sortition
#
# Usage: /mode #chan +sortition:5
# Where 5 denotes an interval of five minutes.
#
# This channel mode de-ops active channel operators and selects a random 1/4 of
# the channel to be operators every n minutes.
# https://en.wikipedia.org/wiki/Sortition
#
# Luke Brooks, 2015
# MIT License

import time
import random

MODE_NAME = "sortition"

__package__ = [{"name": MODE_NAME, "type": "cmode",
                "description": "Implements administrative sortition."}]

_srv_domain = None


def sortition(ctx):
    """
    Invoked when any command is issued in a channel with mode +sortition active.
    Runs a sortition election if the interval has elapsed.
    """
    channel = ctx.get('channel')
    if channel is None:
        return

    duration = int(channel.modes[MODE_NAME][0]) * 60
    then     = channel.modes[MODE_NAME][1]
    now      = int(time.time())

    if (now - then) < duration:
        return

    channel.modes[MODE_NAME][1] = now
    count = int(len(channel.clients) / 4)
    if count == 0:
        count += 1

    administration = random.sample(list(channel.clients), count)

    # Grab a client object to broadcast de-op messages with
    srv_domain = _srv_domain or "irc"
    for broadcast_client in channel.clients:
        break

    # Remove existing channel operators
    for o in channel.ops:
        for n in o:
            broadcast_client.broadcast(channel.name, ':%s MODE %s: -qaohv %s' % \
                (srv_domain, channel.name, n))
        del o[:]

    # Instate the new administration
    for mode in ['q', 'a', 'o', 'h']:
        if mode in channel.supported_modes and mode in channel.modes:
            for c in administration:
                channel.modes[mode].append(c.nick)
                c.broadcast(channel.name, ':%s MODE %s: +%s %s' % \
                    (srv_domain, channel.name, mode, c.nick))
            break


def __init__(ctx):
    global _srv_domain
    __package__[0]["callable"] = sortition
    if hasattr(ctx, 'server') and ctx.server:
        _srv_domain = ctx.server.config.server.domain


def __del__(ctx):
    pass
