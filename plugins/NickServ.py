# NickServ.py plugin for Psyrcd.
# Many thanks to the contributors of Anope.
# Implements /nickserv, usermode R and channel mode c.
# MIT License

# Schema: ip | ident | nick | password | time_reg | time_use
# Colour key:
# \x02 bold
# \x03 coloured text
# \x1D italic text
# \x0F colour reset
# \x16 reverse colour
# \x1F underlined text

import time
import hashlib
import datetime
import logging

TABLE              = "nickserv"
DB_FILE            = "./services.db"
MAX_NICKS          = 3
MAX_RECORDS        = 8192
WAIT_MINUTES       = 0
MAX_DAYS_UNPRESENT = 31

_db         = None
_srv_domain = None

__package__ = [
    {"name": "nickserv", "type": "command",
     "description": "Nickname registration service."},
    {"name": "ns",       "type": "command",
     "description": "Nickname registration service."},
    {"name": "R",        "type": "umode",
     "description": "Registered nickname."},
    {"name": "c",        "type": "cmode",
     "description": "Registered nicknames only."},
]


def _ns_ident():
    return "NickServ!services@" + (_srv_domain or "irc")


def escape(query):
    return query.replace("'", "")


def nsmsg(client, msg):
    client.broadcast(client.nick, ":%s NOTICE %s :%s" % \
        (_ns_ident(), client.nick, msg))


def fmt_timestamp(ts):
    return datetime.datetime.fromtimestamp(int(ts)).strftime('%b %d %H:%M:%S %Y')


def nsmsg_list(client, t):
    for r in t:
        if client.oper:
            ip = " IP: %s," % r['ip']
        else:
            ip = ''
        user = client.server.clients.get(r['nick'])
        if user:
            if 'R' in user.modes:
                nsmsg(client, "\x02\x033%s\x0F:%s Ident: %s, Registered: %s" % \
                    (r['nick'], ip, r['ident'], fmt_timestamp(r['time_reg'])))
            else:
                nsmsg(client, "\x02\x032%s\x0F:%s Ident: %s, Registered: %s" % \
                    (r['nick'], ip, r['ident'], fmt_timestamp(r['time_reg'])))
        else:
            nsmsg(client, "\x02%s\x0F:%s Ident: %s, Registered: %s" % \
                (r['nick'], ip, r['ident'], fmt_timestamp(r['time_reg'])))


def is_expired(seconds):
    t = time.time()
    seconds = t - seconds
    minutes, seconds = divmod(seconds, 60)
    hours,   minutes = divmod(minutes, 60)
    days,    hours   = divmod(hours, 24)
    weeks,   days    = divmod(days, 7)
    return MAX_DAYS_UNPRESENT < days + (weeks * 7)


def _nickserv(ctx):
    """Command handler for /nickserv and /ns."""
    client = ctx.client
    line_body = ctx.line.body
    raw_params = line_body.split(' ', 1)[1].strip() if ' ' in line_body else ''

    client.last_activity = str(time.time())[:10]
    cmd  = raw_params
    args = ''
    if ' ' in raw_params:
        cmd, args = raw_params.split(' ', 1)
        cmd, args = cmd.lower(), args.lower()
    else:
        cmd = raw_params.lower()

    if cmd == 'help' or not cmd:
        if not args:
            nsmsg(client, "\x02/NICKSERV\x0F allows you to \"register\" a nickname")
            nsmsg(client, "and prevent other people from using it. The following")
            nsmsg(client, "commands allow for registration and maintenance of")
            nsmsg(client, "nicknames; to use them, type \x02/NICKSERV \x1Fcommand\x0F.")
            nsmsg(client, "For more information on a specific command, type")
            nsmsg(client, "\x02/NICKSERV HELP \x1Fcommand\x0F.")
            nsmsg(client, "")
            nsmsg(client, "     REGISTER   Register a nickname")
            nsmsg(client, "     IDENTIFY   Identify yourself with your password")
            nsmsg(client, "     PASSWORD   Set your nickname password")
            nsmsg(client, "     DROP       Cancel the registration of a nickname")
            nsmsg(client, "     GHOST      Disconnects a \"ghost\" IRC session using your nick")
            nsmsg(client, "     INFO       Displays information about a given nickname")
            nsmsg(client, "     LIST       List all registered nicknames that match a given pattern")
            nsmsg(client, "     LOGOUT     Reverses the effect of the IDENTIFY command")
            if client.oper:
                nsmsg(client, "     EXPIRE     Manually purge expired registrations")
            nsmsg(client, "")
            nsmsg(client, "Nicknames that are not used anymore are subject to")
            nsmsg(client, "the automatic expiration, i.e. they will be deleted")
            nsmsg(client, "after %i days if not used." % MAX_DAYS_UNPRESENT)
            nsmsg(client, "")
            nsmsg(client, "\x02NOTICE:\x0F This service is intended to provide a way for")
            nsmsg(client, "IRC users to ensure their identity is not compromised.")
            nsmsg(client, "It is \x02NOT\x0F intended to facilitate \"stealing\" of")
            nsmsg(client, "nicknames or other malicious actions. Abuse of NickServ")
            nsmsg(client, "will result in, at minimum, loss of the abused")
            nsmsg(client, "nickname(s).")

        elif args == 'register':
            nsmsg(client, "Syntax: \x02REGISTER <PASSWORD>\x0F")
            nsmsg(client, "Up to \x02%i\x0F nicknames may be registered per IP address." % MAX_NICKS)
            nsmsg(client, "Nicknames will be forgotten about after %i days if not used." % MAX_DAYS_UNPRESENT)

        elif args == 'identify':
            nsmsg(client, "Syntax: \x02IDENTIFY \x1Fpassword\x0F")
            nsmsg(client, "")
            nsmsg(client, "Tells NickServ that you are really the owner of this")
            nsmsg(client, "nick. The password should be the same one you sent with")
            nsmsg(client, "the \x02REGISTER\x0F command.")

        elif args == 'drop':
            nsmsg(client, "Syntax: \x02DROP \x1Fnickname\x0F \x02\x1Fpassword\x0F")
            nsmsg(client, "")
            nsmsg(client, "Drops your nickname from the NickServ database.  A nick")
            nsmsg(client, "that has been dropped is free for anyone to re-register.")
            nsmsg(client, "")
            if client.oper:
                nsmsg(client, "IRC Operators may supply anything as a password.")

        elif args == 'ghost':
            nsmsg(client, "Syntax: \x02GHOST \x1Fnickname\x0F \x02\x1Fpassword\x0F")
            nsmsg(client, "")
            nsmsg(client, "Terminates a \"ghost\" IRC session using your nick.  A")
            nsmsg(client, "\"ghost\" session is one which is not actually connected,")
            nsmsg(client, "but which the IRC server believes is still online for one")
            nsmsg(client, "reason or another.  Typically, this happens if your")
            nsmsg(client, "computer crashes or your Internet or modem connection")
            nsmsg(client, "goes down while you're on IRC.  This command will also")
            nsmsg(client, "disconnect any other users attempting to use a nickname")
            nsmsg(client, "you own.")

        elif args == 'list':
            nsmsg(client, "Syntax: \x02LIST \x1Fpattern\x0F")
            nsmsg(client, "")
            nsmsg(client, "Lists all registered nicknames which match the given")
            nsmsg(client, "pattern, in \x1Fnick!user@host\x0F format.")
            nsmsg(client, "")
            nsmsg(client, "Examples:")
            nsmsg(client, "")
            nsmsg(client, "     \x02LIST *!user@foo.com\x0F")
            nsmsg(client, "         Lists all nicks owned by \x02user@foo.com\x0F.")
            nsmsg(client, "    \x02LIST *Bot*!*@*\x0F")
            nsmsg(client, "        Lists all registered nicks with \x02Bot\x0F in their")
            nsmsg(client, "         names (case insensitive).")
            nsmsg(client, "     \x02LIST *!*@*.bar.org\x0F")
            nsmsg(client, "         Lists all nicks owned by users in the \x02bar.org\x0F")
            nsmsg(client, "         domain.")

        elif args == 'info':
            nsmsg(client, "Syntax: \x02INFO \x1Fnickname\x0F")
            nsmsg(client, "")
            nsmsg(client, "Displays information about the given nickname, such as")
            nsmsg(client, "the ident registered with, whether the user is online, and")
            nsmsg(client, "when the nickname was last logged into.")

        elif args == 'logout':
            nsmsg(client, "Syntax: \x02LOGOUT\x0F")
            nsmsg(client, "")
            nsmsg(client, "This reverses the effect of the \x02IDENTIFY\x0F command, i.e.")
            nsmsg(client, "make you not recognized as the real owner of the nick")
            nsmsg(client, "anymore. Note, however, that you won't be asked to reidentify")
            nsmsg(client, "yourself.")

        elif args == 'password':
            nsmsg(client, "Syntax: \x02PASSWORD \x1Fnew-password\x0F")
            nsmsg(client, "")
            nsmsg(client, "Sets the password for a nickname, providing you are")
            nsmsg(client, "already identified with NickServ. If you have forgotten")
            nsmsg(client, "your password and need it resetting, you will need to")
            nsmsg(client, "speak to an IRC Operator.")
            if client.oper:
                nsmsg(client, "")
                nsmsg(client, "Syntax: \x02PASSWORD \x1Fnick\x0F \x02\x1Fnew-password\x0F")
                nsmsg(client, "IRC Operators may redefine passwords at will.")

        elif args == 'expire' and client.oper:
            nsmsg(client, "Syntax: \x02EXPIRE\x0F")
            nsmsg(client, "")
            nsmsg(client, "This iterates through every record in the database")
            nsmsg(client, "and purges records that haven't been used for over")
            nsmsg(client, "MAX_DAYS_UNPRESENT days, which is currently set to \x02%i\x0F." % MAX_DAYS_UNPRESENT)
            nsmsg(client, "")
            nsmsg(client, "Expiration of a nickname is checked when the \x02IDENTIFY\x0F")
            nsmsg(client, "command is used, however, nicknames may never be claimed")
            nsmsg(client, "at all. This command may take a few seconds to work over ")
            nsmsg(client, "large databases.")

        else:
            nsmsg(client, "Unknown help topic.")

    elif cmd == 'register':
        if 'R' in client.modes:
            nsmsg(client, "You are already identified.")
        else:
            t = divmod(int(client.last_activity) - int(client.connected_at), 60)
            if not args:
                nsmsg(client, "Usage: \x02/NICKSERV REGISTER \x1Fpassword\x0F")
            elif t[0] < WAIT_MINUTES:
                nsmsg(client, "You must be connected for at least %i minutes before you can register." % WAIT_MINUTES)
            else:
                password = hashlib.sha1(args.encode('utf-8')).hexdigest()
                db = _db
                c = db.cursor()
                r = None
                if MAX_RECORDS:
                    c.execute("select count(*) from %s" % TABLE)
                    r = c.fetchone()
                    if r['count(*)'] >= MAX_RECORDS:
                        nsmsg(client, "The NickServ database is full.")
                        return
                c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (client.nick,))
                r = c.fetchone()
                if r:
                    nsmsg(client, "Nickname \x02%s\x0F is already registered." % escape(client.nick))
                else:
                    c.execute("SELECT * FROM %s WHERE ip=?" % TABLE, (client.host[0],))
                    r = c.fetchall()
                    if len(r) >= MAX_NICKS:
                        nsmsg(client, "You already have %i nicknames registered to this ip address:" % MAX_NICKS)
                        for i in r:
                            nsmsg(client, "\x02%s\x0F, %s" % (i['nick'], fmt_timestamp(i['time_reg'])))
                    else:
                        t = time.time()
                        db.execute("INSERT INTO %s VALUES (?,?,?,?,?,?)" % \
                            TABLE, (client.host[0], client.client_ident(True), client.nick, password, t, t,))
                        db.commit()
                        nsmsg(client, "Registered \x02%s\x0F to \x02%s\x0F." % (client.nick, client.client_ident(True)))
                        if 'R' in client.supported_modes:
                            client.modes['R'] = 1
                            client.broadcast(client.nick, ':%s MODE %s +R' % (_ns_ident(), client.nick))

    elif cmd == 'identify':
        if 'R' in client.modes:
            nsmsg(client, "You are already identified.")
        else:
            if not args:
                nsmsg(client, "Usage: \x02/NICKSERV IDENTIFY \x1Fpassword\x0F")
            else:
                warn = ":%s NOTICE * :\x034WARNING\x0F: %s tried to authenticate with an incorrect password." % \
                    (_ns_ident(), client.nick)
                password = hashlib.sha1(args.encode('utf-8')).hexdigest()
                db = _db
                c = db.cursor()
                c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (client.nick,))
                r = c.fetchone()
                if not r:
                    nsmsg(client, "Your nick isn't registered.")
                else:
                    if is_expired(r['time_use']):
                        c.execute("DELETE FROM %s WHERE nick=?" % TABLE, (client.nick,))
                        db.commit()
                        nsmsg(client, "\x02%s\x0F has expired due to inactivity." % client.nick)
                        client.broadcast('umode:W', ':%s NOTICE * :\x02%s\x0F has expired.' % \
                            (_ns_ident(), client.nick))
                    elif r['password'] == password:
                        c.execute("UPDATE %s SET time_use = %f WHERE nick=?" % \
                            (TABLE, time.time()), (client.nick,))
                        db.commit()
                        if 'R' in client.supported_modes:
                            client.modes['R'] = 1
                            nsmsg(client, "Authentication successful for \x02%s\x0F." % client.nick)
                            client.broadcast(client.nick, ':%s MODE %s +R' % (_ns_ident(), client.nick))
                    else:
                        nsmsg(client, "Incorrect password.")
                        client.broadcast('umode:W', warn)

    elif cmd == 'password':
        if not args or (' ' in args and not client.oper):
            nsmsg(client, "Usage: \x02/NICKSERV PASSWORD \x1Fnew-password\x0F")
        elif client.oper and ' ' in args:
            nick, password = args.split()
            password = hashlib.sha1(password.encode('utf-8')).hexdigest()
            db = _db
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (nick,))
            r = c.fetchone()
            if not r:
                nsmsg(client, "\x02%s\x0F isn't registered." % nick)
            else:
                c.execute("UPDATE %s SET password=? WHERE nick=?" % TABLE, (password, nick))
                db.commit()
                nsmsg(client, "Changed password for \x02%s\x0F." % escape(nick))
        else:
            password = hashlib.sha1(args.encode('utf-8')).hexdigest()
            db = _db
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (client.nick,))
            r = c.fetchone()
            if not r:
                nsmsg(client, "\x02%s\x0F isn't registered." % client.nick)
            else:
                if 'R' not in client.modes:
                    nsmsg(client, "You must be identified.")
                    nsmsg(client, "Contact an IRC Operator for help retrieving accounts.")
                    client.broadcast('umode:W', ':%s NOTICE * :\x02%s\x0F needs help resetting their password.' % (_ns_ident(), client.nick))
                    client.broadcast('umode:W', ':%s NOTICE * :%s is connecting from \x02%s\x0F and registered from \x02%s\x0F.' % \
                        (_ns_ident(), client.nick, client.host[0], r['ip']))
                else:
                    c.execute("UPDATE %s SET password=? WHERE nick=?" % TABLE, (password, client.nick))
                    db.commit()
                    nsmsg(client, "Changed password for \x02%s\x0F." % escape(client.nick))

    elif cmd == 'ghost':
        if not args or ' ' not in args:
            nsmsg(client, "Usage: \x02/NICKSERV GHOST \x1Fnick\x0F \x02\x1Fpassword\x0F")
        else:
            nick, password = args.split()
            password = hashlib.sha1(password.encode('utf-8')).hexdigest()
            user = client.server.clients.get(nick)
            if not user:
                nsmsg(client, "Unknown nick.")
            else:
                db = _db
                c = db.cursor()
                c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (nick,))
                r = c.fetchone()
                if not r:
                    nsmsg(client, "\x02%s\x0F isn't registered." % client.nick)
                else:
                    if r['password'] != password:
                        nsmsg(client, "Incorrect password.")
                        warn = ":%s NOTICE * :\x034WARNING\x0F: %s tried to ghost %s with an incorrect password." % \
                            (_ns_ident(), client.nick, nick)
                        client.broadcast('umode:W', warn)
                    else:
                        user.finish(':%s QUIT :GHOST command used by %s.' % (user.client_ident(True), client.nick))
                        nsmsg(client, "Client with your nickname has been killed.")

    elif cmd == 'list':
        if not args:
            nsmsg(client, "Usage \x02/NICKSERV LIST \x1Fpattern\x0F")
        else:
            if not client.oper and 'R' not in client.modes:
                nsmsg(client, "Access denied.")
            else:
                args = escape(args.replace('*', '%'))
                db = _db
                c = db.cursor()
                c.execute("SELECT * FROM %s WHERE ident LIKE ?" % TABLE, (args,))
                t = c.fetchall()
                nsmsg_list(client, t)

    elif cmd == 'logout':
        if 'R' in client.modes:
            del client.modes['R']
            client.broadcast(client.nick, ":%s MODE %s -R" % (_ns_ident(), client.nick))
            nsmsg(client, "Successfully logged out.")
        else:
            nsmsg(client, "You're not logged in.")

    elif cmd == 'info':
        if not args:
            nsmsg(client, "Usage: \x02/NICKSERV INFO \x1FNICK\x0F")
        else:
            db = _db
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (args,))
            r = c.fetchone()
            if not r:
                nsmsg(client, "\x02%s\x0F isn't registered." % args)
            else:
                nsmsg(client, "%s is %s" % (args, r['ident']))
                if client.oper:
                    nsmsg(client, "Registered from: %s" % r['ip'])
                user = client.server.clients.get(r['nick'])
                if user:
                    nsmsg(client, " Is online from: %s" % user.client_ident(True).split("!")[1])
                nsmsg(client, "     Last login: %s" % fmt_timestamp(r['time_use']))
                if user:
                    nsmsg(client, " Last seen time: %s" % fmt_timestamp(user.last_activity))
                nsmsg(client, "Time registered: %s" % fmt_timestamp(r['time_reg']))

    elif cmd == 'drop':
        if not args or ' ' not in args:
            nsmsg(client, "Usage: \x02/NICKSERV DROP \x1Fnick\x0F \x02\x1Fpassword\x0F")
        else:
            nick, password = args.split()
            password = hashlib.sha1(password.encode('utf-8')).hexdigest()
            db = _db
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (nick,))
            r = c.fetchone()
            if not r:
                nsmsg(client, "\x02%s\x0F isn't registered." % nick)
            else:
                if client.oper or (r['password'] == password):
                    c.execute("DELETE FROM %s WHERE nick=?" % TABLE, (nick,))
                    db.commit()
                    nsmsg(client, "\x02%s\x0F has been dropped." % nick)
                    client.broadcast('umode:W', ':%s NOTICE * :%s has dropped the nick \x02%s\x0F.' % \
                        (_ns_ident(), client.nick, nick))
                    user = client.server.clients.get(nick)
                    if user and 'R' in user.modes:
                        del user.modes['R']
                        client.broadcast(user.nick, ":%s MODE %s -R" % (_ns_ident(), client.nick))
                else:
                    nsmsg(client, "Incorrect password.")
                    warn = ":%s NOTICE * :\x034WARNING\x0F: %s tried to DROP %s with an incorrect password." % \
                        (_ns_ident(), client.nick, nick)
                    client.broadcast('umode:W', warn)

    elif cmd == "expire":
        if not client.oper:
            nsmsg(client, "Unknown command.")
            nsmsg(client, "Use \x02/NICKSERV HELP\x0F for a list of available commands.")
        else:
            db = _db
            c = db.cursor()
            c.execute("SELECT * FROM %s" % TABLE)
            t = c.fetchall()
            for r in t:
                if is_expired(r['time_use']):
                    c.execute("DELETE FROM %s WHERE nick=?" % TABLE, (r['nick'],))
                    nsmsg(client, "\x02%s\x0F has expired due to inactivity." % r['nick'])
                    client.broadcast('umode:W', ':%s NOTICE * :%s expired \x02%s\x0F.' % (_ns_ident(), client.nick, r['nick']))
            db.commit()
            nsmsg(client, "All registrations have been cycled through.")

    elif cmd == "debug":
        if client.oper:
            db = _db
            c = db.cursor()
            c.execute("select count(*) from %s" % TABLE)
            r = c.fetchone()
            nsmsg(client, str(r['count(*)']))
        nsmsg(client, "You are likely to be eaten by a \x02\x034Grue\x0F.")

    else:
        nsmsg(client, "Unknown command.")
        nsmsg(client, "Use \x02/NICKSERV HELP\x0F for a list of available commands.")


def umode_R(ctx):
    """
    Invoked on new connections (new=True) and when a user with umode R issues
    any IRC command (func interception).
    """
    client = ctx.client

    if ctx.get('new'):
        # New connection: notify client if their nick is registered.
        if client.nick:
            db = _db
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (client.nick,))
            r = c.fetchone()
            if r:
                nsmsg(client, "This nickname is owned by \x02%s\x0F." % r['ident'])
            else:
                nsmsg(client, "Use \x02/NICKSERV HELP REGISTER\x0F for information on registering this nick.")
                if WAIT_MINUTES:
                    nsmsg(client, "You must be connected for at least %i minutes before you can register." % WAIT_MINUTES)
        return

    func   = ctx.get('func')
    params = ctx.get('params', '')

    if func is None:
        return

    if func.__name__ == 'handle_nick':
        db = _db
        c = db.cursor()
        c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (params,))
        r = c.fetchone()
        if 'R' in client.modes:
            del client.modes['R']
            client.broadcast(client.nick, ":%s MODE %s -R" % (_ns_ident(), client.nick))
        if r:
            nsmsg(client, "This nickname is owned by \x02%s\x0F." % r['ident'])


def cmode_c(ctx):
    """
    Invoked when any command is issued in a channel with mode +c active.
    Blocks users without umode R from joining.
    """
    client  = ctx.client
    channel = ctx.get('channel')
    func    = ctx.get('func')

    if func is None or channel is None:
        return

    if func.__name__ == 'handle_join':
        if 'c' in channel.modes and 'R' not in client.modes:
            nsmsg(client, "A registered nick is required to join %s." % channel.name)
            ctx["params"] = ''


def __init__(ctx):
    global _db, _srv_domain
    for pkg in __package__:
        if pkg["name"] in ("nickserv", "ns"):
            pkg["callable"] = _nickserv
        elif pkg["name"] == "R":
            pkg["callable"] = umode_R
        elif pkg["name"] == "c":
            pkg["callable"] = cmode_c

    if hasattr(ctx, 'server') and ctx.server:
        _srv_domain = ctx.server.config.server.domain

    if _db is None:
        import sqlite3
        db = sqlite3.connect(DB_FILE, check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute("CREATE TABLE IF NOT EXISTS %s "
                   "(ip, ident, nick, password, time_reg REAL, time_use REAL)" % TABLE)
        db.commit()
        _db = db


def __del__(ctx):
    global _db
    if _db is not None:
        _db.close()
        _db = None
