# replace.py plugin for Psyrcd.
# Implements channel mode +G.
#
# This channel mode replaces phrases in privmsg lines.
# Usage: /quote mode #channel +G:from_phrase,to_phrase,...
#        /quote mode #channel -G:phrase1,...
#
# Luke Brooks, 2015
# MIT License

from copy import deepcopy

__package__ = [{"name": "G", "type": "cmode",
                "description": "Substitutes phrases."}]


def G(ctx):
    """
    Invoked when a command is issued in a channel with mode +G active.
    Intercepts handle_privmsg to perform phrase substitution.
    """
    func    = ctx.get('func')
    channel = ctx.get('channel')

    if func is None or channel is None:
        return

    if func.__name__ == "handle_privmsg":
        params = ctx.get('params', '')
        parts = params.split(":", 1)
        if len(parts) < 2:
            return
        line = parts[1].split()
        for arg in channel.modes.get("G", []):
            if isinstance(arg, tuple):
                for i, phrase in enumerate(line):
                    if phrase.lower() == arg[0].lower():
                        line[i] = arg[1]
        parts[1] = ' '.join(line)
        ctx["params"] = ':'.join(parts)


def __init__(ctx):
    __package__[0]["callable"] = G


def __del__(ctx):
    pass
