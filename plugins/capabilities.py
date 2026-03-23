# capabilities.py plugin for Psyrcd.
# Implements IRCv3 CAP negotiation so clients like irssi can connect
# without -nocap.  Registers a 'cap' command that replaces the broken
# built-in handle_cap (which used params[0] — a single character — as
# the subcommand, so 'LS'/'END' comparisons never matched).
#
# The welcome burst is left to the built-in handle_nick; we do not defer
# it, because irssi batches CAP LS + NICK + USER in one TCP write and
# never sends a CAP END in that flow, causing a deadlock if the burst is
# gated on cap_negotiated.
#
# Luke Brooks, 2015 (updated 2026)
# MIT License

__package__ = [
    {"name": "cap", "type": "command", "description": "IRCv3 capability negotiation."},
]


def cap(ctx):
    """Handle IRCv3 CAP negotiation (LS, REQ, END, LIST)."""
    client = ctx.client
    line   = ctx.line.body

    # line is e.g. "CAP LS 302", "CAP END", "CAP REQ :multi-prefix"
    parts  = line.split(None, 2)
    subcmd = parts[1].upper() if len(parts) > 1 else 'LS'
    rest   = parts[2] if len(parts) > 2 else ''

    srv  = client.server.servername
    nick = client.nick or '*'

    if subcmd == 'LS':
        return ':%s CAP %s LS :' % (srv, nick)

    if subcmd == 'LIST':
        return ':%s CAP %s LIST :' % (srv, nick)

    if subcmd == 'REQ':
        caps = rest.lstrip(':').strip()
        return ':%s CAP %s NAK :%s' % (srv, nick, caps)

    if subcmd == 'END':
        client.cap_negotiated = True
        return ''

    return ':%s CAP %s LS :' % (srv, nick)


def __init__(ctx):
    __package__[0]["callable"] = cap


def __del__(ctx):
    pass
