# NickServ.py for Psyrcd.
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

log                = cache['config']['logging']
TABLE              = "nickserv"
DB_FILE            = "./services.db"
NS_IDENT           = "NickServ!services@" + cache['config']['SRV_DOMAIN']
MAX_NICKS          = 3
MAX_RECORDS        = 8192
WAIT_MINUTES       = 0
MAX_DAYS_UNPRESENT = 31

def escape(query): return query.replace("'","")

def nsmsg(msg):
    client.broadcast(client.nick, ":%s NOTICE %s :%s" % \
    (NS_IDENT, client.nick, msg))

def fmt_timestamp(ts): return datetime.datetime.fromtimestamp(int(ts)).strftime('%b %d %H:%M:%S %Y')

def nsmsg_list(t):
    for r in t:
        if client.oper: ip = " IP: %s," % r['ip']
        else: ip = ''
        user = client.server.clients.get(r['nick'])
        if user:
            if 'R' in user.modes: nsmsg("\x02\x033%s\x0F:%s Ident: %s, Registered: %s" % \
                (r['nick'], ip, r['ident'], fmt_timestamp(r['time_reg'])))
            else: nsmsg("\x02\x032%s\x0F:%s Ident: %s, Registered: %s" % \
                (r['nick'], ip, r['ident'], fmt_timestamp(r['time_reg'])))
        else: nsmsg("\x02%s\x0F:%s Ident: %s, Registered: %s" % \
            (r['nick'], ip, r['ident'], fmt_timestamp(r['time_reg'])))

def is_expired(seconds):
    t = time.time()
    seconds = t - seconds
    minutes, seconds = divmod(seconds, 60)
    hours,   minutes = divmod(minutes, 60)
    days,    hours   = divmod(hours, 24)
    weeks,   days    = divmod(days, 7)
    if MAX_DAYS_UNPRESENT >= days+(weeks*7):
        return False
    else:
        return True

class NSError(Exception):
    def __init__(self, value): self.value = value # causes error messages to be
    def __str__(self): return(repr(self.value))   # dispersed to umode:W users

if 'init' in dir():
    provides=['command:nickserv,ns:Nickname registration service.', 'umode:R:Registered nickname.',
        'cmode:c:Registered nicknames only.']
    if init:
        # You generally want to have your imports here and then put them on the
        # cache so they're not recomputed for every sentence said in an associated channel
        # or command executed by a similar user, just because you're using the --debug flag.

        # Reader beware: sqlite3 is only being used in keeping with the ethos "only the stdlib".
        # Feel free to implement /your/ modules with SQLAlchemy, Dataset, PyMongo, PyTables.. SciKit.. NLTK..
        if not 'db' in cache:
            import sqlite3
            db = sqlite3.connect(DB_FILE, check_same_thread=False)
            db.row_factory = sqlite3.Row
            cache['db'] = db
            db.execute("CREATE TABLE IF NOT EXISTS %s (ip, ident, nick, password, time_reg REAL, time_use REAL)" % TABLE)
            db.commit()
    else:
        if 'db' in cache:
            cache['db'].close()
            del cache['db']

if 'display' in dir() and 'channel' in dir(): output = 'Registered nicks only.'

# The following happens when the server detects
# that a user carrying our umode is doing something.
# Here we can determine what the client is doing, and then
# modify the client, the server, and/or command parameters.
if 'func' in dir():
    if func.__name__ == 'handle_join':
        if 'channel' in dir():
            if 'c' in channel.modes and not 'R' in client.modes:
                nsmsg("A registered nick is required to join %s." % channel.name)
                params = ''

    if func.__name__ == 'handle_nick':
        db = cache['db']
        c = db.cursor()
        c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (params,))
        r = c.fetchone()
        if 'R' in client.modes:
            del client.modes['R']
            client.broadcast(client.nick, ":%s MODE %s -R" % (NS_IDENT,client.nick))
        if r: nsmsg("This nickname is owned by \x02%s\x0F." % r['ident'])
        del db,c,r

# This namespace indicates a client is connecting:
if 'new' in dir() and 'channel' not in dir():
    # In this instance we only care if the client
    # obtained their default nickname.
    if client.nick:
        db = cache['db']
        c = db.cursor()
        c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (client.nick,))
        r = c.fetchone()
        if r: nsmsg("This nickname is owned by \x02%s\x0F." % r['ident'])
        else: 
            nsmsg("Use \x02/NICKSERV HELP REGISTER\x0F for information on registering this nick.")
            if WAIT_MINUTES:
                nsmsg("You must be connected for at least %i minutes before you can register." % WAIT_MINUTES)
        del c, r

if 'command' in dir():
    client.last_activity = str(time.time())[:10]
    cmd=params
    args=''
    if ' ' in params:
        cmd,args = params.split(' ',1)
        cmd,args=(cmd.lower(),args.lower())
    if cmd == 'help' or not cmd:
        if not args:
            nsmsg("\x02/NICKSERV\x0F allows you to \"register\" a nickname")
            nsmsg("and prevent other people from using it. The following")
            nsmsg("commands allow for registration and maintenance of")
            nsmsg("nicknames; to use them, type \x02/NICKSERV \x1Fcommand\x0F.")
            nsmsg("For more information on a specific command, type")
            nsmsg("\x02/NICKSERV HELP \x1Fcommand\x0F.")
            nsmsg("")
            nsmsg("     REGISTER   Register a nickname")
            nsmsg("     IDENTIFY   Identify yourself with your password")
            nsmsg("     PASSWORD   Set your nickname password")
            nsmsg("     DROP       Cancel the registration of a nickname")
            nsmsg("     GHOST      Disconnects a \"ghost\" IRC session using your nick")
            nsmsg("     INFO       Displays information about a given nickname")
            nsmsg("     LIST       List all registered nicknames that match a given pattern")
            nsmsg("     LOGOUT     Reverses the effect of the IDENTIFY command")
            if client.oper:
                nsmsg("     EXPIRE     Manually purge expired registrations")
            nsmsg("")
            nsmsg("Nicknames that are not used anymore are subject to")
            nsmsg("the automatic expiration, i.e. they will be deleted")
            nsmsg("after %i days if not used." % MAX_DAYS_UNPRESENT)
            nsmsg("")
            nsmsg("\x02NOTICE:\x0F This service is intended to provide a way for")
            nsmsg("IRC users to ensure their identity is not compromised.")
            nsmsg("It is \x02NOT\x0F intended to facilitate \"stealing\" of")
            nsmsg("nicknames or other malicious actions. Abuse of NickServ")
            nsmsg("will result in, at minimum, loss of the abused")
            nsmsg("nickname(s).")

        elif args == 'register':
            nsmsg("Syntax: \x02REGISTER <PASSWORD>\x0F")
            nsmsg("Up to \x02%i\x0F nicknames may be registered per IP address." % MAX_NICKS)
            nsmsg("Nicknames will be forgotten about after %i days if not used." % MAX_DAYS_UNPRESENT)

        elif args == 'identify':
            nsmsg("Syntax: \x02IDENTIFY \x1Fpassword\x0F")
            nsmsg("")
            nsmsg("Tells NickServ that you are really the owner of this")
            nsmsg("nick. The password should be the same one you sent with")
            nsmsg("the \x02REGISTER\x0F command.")

        elif args == 'drop':
            nsmsg("Syntax: \x02DROP \x1Fnickname\x0F \x02\x1Fpassword\x0F")
            nsmsg("")
            nsmsg("Drops your nickname from the NickServ database.  A nick")
            nsmsg("that has been dropped is free for anyone to re-register.")
            nsmsg("")
            if client.oper:
                nsmsg("IRC Operators may supply anything as a password.")

        elif args == 'ghost':
            nsmsg("Syntax: \x02GHOST \x1Fnickname\x0F \x02\x1Fpassword\x0F")
            nsmsg("")
            nsmsg("Terminates a \"ghost\" IRC session using your nick.  A")
            nsmsg("\"ghost\" session is one which is not actually connected,")
            nsmsg("but which the IRC server believes is still online for one")
            nsmsg("reason or another.  Typically, this happens if your")
            nsmsg("computer crashes or your Internet or modem connection")
            nsmsg("goes down while you're on IRC.  This command will also")
            nsmsg("disconnect any other users attempting to use a nickname")
            nsmsg("you own.")

        elif args == 'list':
            nsmsg("Syntax: \x02LIST \x1Fpattern\x0F")
            nsmsg("")
            nsmsg("Lists all registered nicknames which match the given")
            nsmsg("pattern, in \x1Fnick!user@host\x0F format.")
            nsmsg("")
            nsmsg("Examples:")
            nsmsg("")
            nsmsg("     \x02LIST *!user@foo.com\x0F")
            nsmsg("         Lists all nicks owned by \x02user@foo.com\x0F.")
            nsmsg("    \x02LIST *Bot*!*@*\x0F")
            nsmsg("        Lists all registered nicks with \x02Bot\x0F in their")
            nsmsg("         names (case insensitive).")
            nsmsg("     \x02LIST *!*@*.bar.org\x0F")
            nsmsg("         Lists all nicks owned by users in the \x02bar.org\x0F")
            nsmsg("         domain.")

        elif args == 'info':
            nsmsg("Syntax: \x02INFO \x1Fnickname\x0F")
            nsmsg("")
            nsmsg("Displays information about the given nickname, such as")
            nsmsg("the ident registered with, whether the user is online, and")
            nsmsg("when the nickname was last logged into.")

        elif args == 'logout':
            nsmsg("Syntax: \x02LOGOUT\x0F")
            nsmsg("")
            nsmsg("This reverses the effect of the \x02IDENTIFY\x0F command, i.e.")
            nsmsg("make you not recognized as the real owner of the nick")
            nsmsg("anymore. Note, however, that you won't be asked to reidentify")
            nsmsg("yourself.")

        elif args == 'password':
            nsmsg("Syntax: \x02PASSWORD \x1Fnew-password\x0F")
            nsmsg("")
            nsmsg("Sets the password for a nickname, providing you are")
            nsmsg("already identified with NickServ. If you have forgotten")
            nsmsg("your password and need it resetting, you will need to")
            nsmsg("speak to an IRC Operator.")
            if client.oper:
                nsmsg("")
                nsmsg("Syntax: \x02PASSWORD \x1Fnick\x0F \x02\x1Fnew-password\x0F")
                nsmsg("IRC Operators may redefine passwords at will.")

        elif args == 'expire' and client.oper:
            nsmsg("Syntax: \x02EXPIRE\x0F")
            nsmsg("")
            nsmsg("This iterates through every record in the database")
            nsmsg("and purges records that haven't been used for over")
            nsmsg("MAX_DAYS_UNPRESENT days, which is currently set to \x02%i\x0F." % MAX_DAYS_UNPRESENT)
            nsmsg("")
            nsmsg("Expiration of a nickname is checked when the \x02IDENTIFY\x0F")
            nsmsg("command is used, however, nicknames may never be claimed")
            nsmsg("at all. This command may take a few seconds to work over ")
            nsmsg("large databases.")

        else:
            nsmsg("Unknown help topic.")

    elif cmd == 'register':
        if 'R' in client.modes:
            nsmsg("You are already identified.")
        else:
            t = divmod(int(client.last_activity) - int(client.connected_at), 60)
            if not args: nsmsg("Usage: \x02/NICKSERV REGISTER \x1Fpassword\x0F")
            elif t[0] < WAIT_MINUTES:
                nsmsg("You must be connected for at least %i minutes before you can register." % WAIT_MINUTES)
            else:
                password = hashlib.sha1(args.encode('utf-8')).hexdigest()
                db = cache['db']
                c = db.cursor()
                r = None
                if MAX_RECORDS:
                    c.execute("select count(*) from %s" % TABLE)
                    r = c.fetchone()
                    if r['count(*)'] >= MAX_RECORDS:
                        nsmsg("The NickServ database is full.")
                        raise NSError("MAX_RECORDS has been reached")
                c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (client.nick,))
                r = c.fetchone()
                if r: nsmsg("Nickname \x02%s\x0F is already registered." % escape(client.nick))
                else:
                    c.execute("SELECT * FROM %s WHERE ip=?" % TABLE, (client.host[0],))
                    r = c.fetchall()
                    if len(r) >= MAX_NICKS:
                        nsmsg("You already have %i nicknames registered to this ip address:" % MAX_NICKS)
                        for i in r: nsmsg("\x02%s\x0F, %s" % (i['nick'],fmt_timestamp(i['time_reg'])))
                        del i
                    else:
                        t = time.time()
                        db.execute("INSERT INTO %s VALUES (?,?,?,?,?,?)" % \
                            TABLE, (client.host[0], client.client_ident(True), client.nick, password, t,t,))
                        db.commit()
                        nsmsg("Registered \x02%s\x0F to \x02%s\x0F." % (client.nick,client.client_ident(True)))
                        if 'R' in client.supported_modes:
                            client.modes['R'] = 1
                            client.broadcast(client.nick,':%s MODE %s +R' % (NS_IDENT,client.nick))
                del db,c,r

    elif cmd == 'identify':
        if 'R' in client.modes:
            nsmsg("You are already identified.")
        else:
            if not args: nsmsg("Usage: \x02/NICKSERV IDENTIFY \x1Fpassword\x0F")
            else:
                warn = ":%s NOTICE * :\x034WARNING\x0F: %s tried to authenticate with an incorrect password." % \
                    (NS_IDENT, client.nick)
                password = hashlib.sha1(args.encode('utf-8')).hexdigest()
                db = cache['db']
                c = db.cursor()
                c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (client.nick,))
                r = c.fetchone()
                if not r: nsmsg("Your nick isn't registered.")
                else:
                    if is_expired(r['time_use']):
                        c.execute("DELETE FROM %s WHERE nick=?" % TABLE, (client.nick,))
                        db.commit()
                        nsmsg("\x02%s\x0F has expired due to inactivity." % nick)
                        client.broadcast('umode:W',':%s NOTICE * :\x02%s\x0F has expired.' % \
                            (NS_IDENT, client.nick, client.nick))
                    elif r['password'] == password:
                        c.execute("UPDATE %s SET time_use = %f WHERE nick=?" % \
                            (TABLE, time.time()), (client.nick,))
                        db.commit()
                        if 'R' in client.supported_modes:
                            client.modes['R'] = 1
                            nsmsg("Authentication successful for \x02%s\x0F." % client.nick)
                            client.broadcast(client.nick,':%s MODE %s +R' % (NS_IDENT,client.nick))
                    else:
                        nsmsg("Incorrect password.")
                        client.broadcast('umode:W', warn)
                del warn,db,c,r

    elif cmd == 'password':
        if not args or (' ' in args and not client.oper):
            nsmsg("Usage: \x02/NICKSERV PASSWORD \x1Fnew-password\x0F")
        # Opers: /ns password target-nick new-password
        elif client.oper and ' ' in args:
            nick,password = args.split()
            password = hashlib.sha1(password).hexdigest()
            db = cache['db']
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (nick,))
            r = c.fetchone()
            if not r: nsmsg("\x02%s\x0F isn't registered." % nick)
            else:
                c.execute("UPDATE %s SET password=? WHERE nick=?" % \
                    TABLE, (password, nick))
                nsmsg("Changed password for \x02%s\x0F." % escape(nick))
            del db,c,r
        else:
            password = hashlib.sha1(args).hexdigest()
            db = cache['db']
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE nick=?" % \
                TABLE, (client.nick,))
            r = c.fetchone()
            if not r: nsmsg("\x02%s\x0F isn't registered." % nick)
            else:
                if not 'R' in client.modes:
                    nsmsg("You must be identified.")
                    nsmsg("Contact an IRC Operator for help retrieving accounts.")
                    client.broadcast('umode:W', ':%s NOTICE * :\x02%s\x0F needs help resetting their password.' % (NS_IDENT, client.nick))
                    client.broadcast('umode:W', ':%s NOTICE * :%s is connecting from \x02%s\x0F and registered from \x02%s\x0F.' % \
                        (NS_IDENT, client.nick,client.host[0],r['ip']))
                else:
                    c.execute("UPDATE %s SET password=? WHERE nick=?" % \
                        TABLE, (password, client.nick))
                    nsmsg("Changed password for \x02%s\x0F." % escape(client.nick))
            del db,c,r

    elif cmd == 'ghost':
        if not args or not ' ' in args: nsmsg("Usage: \x02/NICKSERV GHOST \x1Fnick\x0F \x02\x1Fpassword\x0F")
        else:
            nick,password = args.split()
            password = hashlib.sha1(password).hexdigest()
            user = client.server.clients.get(nick)
            if not user: nsmsg("Unknown nick.")
            else:
                db = cache['db']
                c = db.cursor()
                c.execute("SELECT * FROM %s WHERE nick=?" % \
                    TABLE, (nick,))
                r = c.fetchone()
                if not r: nsmsg("\x02%s\x0F isn't registered." % client.nick)
                else:
                    if r['password'] != password:
                        nsmsg("Incorrect password.")
                        warn = ":%s NOTICE * :\x034WARNING\x0F: %s tried to ghost %s with an incorrect password." % \
                            (NS_IDENT,client.nick,nick)
                        client.broadcast('umode:W', warn)
                    else:
                        user.finish(':%s QUIT :GHOST command used by %s.' % (user.client_ident(True), client.nick))
                        nsmsg("Client with your nickname has been killed.")
                del db,c,r
                
    elif cmd == 'list':
        if not args: nsmsg("Usage \x02/NICKSERV LIST \x1Fpattern\x0F")
        else:
            if not client.oper and 'R' not in client.modes:
                nsmsg("Access denied.")
            else:
                args = escape(args.replace('*','%'))
                db = cache['db']
                c = db.cursor()
                c.execute("SELECT * FROM %s WHERE ident LIKE ?" % TABLE,(args,))
                t = c.fetchall()
                nsmsg_list(t)
                del db,c,t

    elif cmd == 'logout':
        if 'R' in client.modes:
            del client.modes['R']
            client.broadcast(client.nick, ":%s MODE %s -R" % (NS_IDENT,client.nick))
            nsmsg("Successfully logged out.")
        else:
            nsmsg("You're not logged in.")

    elif cmd == 'info':
        if not args: nsmsg("Usage: \x02/NICKSERV INFO \x1FNICK\x0F")
        else:
            db =cache['db']
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE nick=?" % TABLE, (args,))
            r = c.fetchone()
            if not r: nsmsg("\x02%s\x0F isn't registered." % args)
            else: 
                nsmsg("%s is %s" % (args,r['ident']))
                if client.oper:
                    nsmsg("Registered from: %s" % r['ip'])
                user = client.server.clients.get(r['nick'])
                if user:
                    nsmsg(" Is online from: %s" % user.client_ident(True).split("!")[1])
                nsmsg("     Last login: %s" % fmt_timestamp(r['time_use']))
                if user:
                    nsmsg(" Last seen time: %s" % \
                        fmt_timestamp(user.last_activity))
                nsmsg("Time registered: %s" % fmt_timestamp(r['time_reg']))
            del db,c,r

    elif cmd == 'drop':
        if not args or not ' ' in args: nsmsg("Usage: \x02/NICKSERV DROP \x1Fnick\x0F \x02\x1Fpassword\x0F")
        else:
            nick,password = args.split()
            password = hashlib.sha1(password).hexdigest()
            db = cache['db']
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE nick=?" % \
                TABLE, (nick,))
            r = c.fetchone()
            if not r: nsmsg("\x02%s\x0F isn't registered." % nick)
            else:
                # IRC Operators can supply anything as a password.
                if client.oper or (r['password'] == password):
                    c.execute("DELETE FROM %s WHERE nick=?" % \
                        TABLE, (nick,))
                    db.commit()
                    nsmsg("\x02%s\x0F has been dropped." % nick)
                    client.broadcast('umode:W',':%s NOTICE * :%s has dropped the nick \x02%s\x0F.' % \
                        (NS_IDENT, client.nick, nick))
                    user = client.server.clients.get(nick)
                    if user and 'R' in user.modes:
                        del user.modes['R']
                        client.broadcast(user.nick, ":%s MODE %s -R" % (NS_IDENT,client.nick))
                else:
                    nsmsg("Incorrect password.")
                    warn = ":%s NOTICE * :\x034WARNING\x0F: %s tried to DROP %s with an incorrect password." % \
                        (NS_IDENT, client.nick, nick)
                    client.broadcast('umode:W', warn)
            del db,c,r

    elif cmd == "expire":
        if not client.oper:
            nsmsg("Unknown command.")
            nsmsg("Use \x02/NICKSERV HELP\x0F for a list of available commands.")
        else:
            db = cache['db']
            c = db.cursor()
            c.execute("SELECT * FROM %s" % TABLE)
            t = c.fetchall()
            for r in t:
                if is_expired(r['time_use']):
                    c.execute("DELETE FROM %s WHERE nick=?" % TABLE, (r['nick'],))
                    nsmsg("\x02%s\x0F has expired due to inactivity." % r['nick'])
                    client.broadcast('umode:W',':%s NOTICE * :%s expired \x02%s\x0F.' % (NS_IDENT, client.nick, r['nick']))
            db.commit()
            nsmsg("All registrations have been cycled through.")
            del db,c,r,t

    elif cmd == "debug":
        if client.oper:
            db = cache['db']
            c = db.cursor()
            c.execute("select count(*) from %s" % TABLE)
            r = c.fetchone()
            nsmsg(r['count(*)'])
        nsmsg("You are likely to be eaten by a \x02\x034Grue\x0F.")

    else:
        nsmsg("Unknown command.")
        nsmsg("Use \x02/NICKSERV HELP\x0F for a list of available commands.")

