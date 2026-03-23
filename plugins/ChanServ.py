# ChanServ.py plugin for Psyrcd.
# Many many thanks to the contributors of Anope.
# Implements /chanserv and channel mode R.
# MIT License

# Schema: channel | password | description | owner | operators | bans | topic | topic_by | topic_time | time_reg | time_use |
#         successor | url | email | entrymsg | mlock | keeptopic | peace | restricted | secureops | signkick | topiclock | modes | protected
# Colour key:
# \x02 bold
# \x03 coloured text
# \x1D italic text
# \x0F colour reset
# \x16 reverse colour
# \x1F underlined text

import re
import time
import hashlib
import datetime

TABLE           = "chanserv"
NS_TABLE        = "nickserv"
DB_FILE         = "./services.db"
MAX_OPS         = False
MAX_RECORDS     = 5000
MAX_CHANNELS    = 25
MAX_DAYS_UNUSED = 62

_db         = None
_srv_domain = None

__package__ = [
    {"name": "chanserv", "type": "command",
     "description": "Channel registration service."},
    {"name": "cs",       "type": "command",
     "description": "Channel registration service."},
    {"name": "R",        "type": "cmode",
     "description": "Registered channel."},
]


def _cs_ident():
    return "ChanServ!services@" + (_srv_domain or "irc")


class Channel(object):
    """
    A dictionary-like object for channel records.
    """
    def __init__(self, channel):
        self.channel = channel
        self.db = _db
        self.c = self.db.cursor()
        self.c.execute("SELECT * FROM %s WHERE channel=?" % TABLE, (self.channel,))
        self.r = self.c.fetchone()
        if not self.r:
            self.channel = ''

    def __getitem__(self, key):
        self.c.execute("SELECT * FROM %s WHERE channel=?" % TABLE, (self.channel,))
        self.r = self.c.fetchone()
        if self.r and key in self.r.keys():
            if key in ['operators', 'modes', 'bans', 'protected']:
                if ':' in self.r[key]:
                    return dict([x.split(':') for x in self.r[key].split(',')])
                else:
                    return dict()
            else:
                return self.r[key]
        else:
            raise CSError("Invalid key")

    def __setitem__(self, key, value):
        if self.r:
            if ':' in key:
                k, v = key.split(':')
                o = self[k]
                if type(o) == dict:
                    if MAX_OPS and (k == 'operators'):
                        if v not in o and len(o) >= MAX_OPS:
                            return
                    o[v] = value
                    v = str(o)\
                        .replace('{', '')\
                        .replace('}', '')\
                        .replace("u'", '')\
                        .replace(' ', '')\
                        .replace("'", '')
                    self.c.execute("UPDATE %s SET %s=? WHERE channel=?" % (TABLE, k), (v, self.channel))
                    self.db.commit()
            elif key in self.r.keys():
                self.c.execute("UPDATE %s SET %s=? WHERE channel=?" % (TABLE, key), (value, self.channel))
                self.db.commit()
            else:
                raise CSError("Invalid key")
        else:
            raise CSError("Invalid channel")

    def __delitem__(self, key):
        if ':' in key:
            k, v = key.split(':')
            o = self[k]
            if type(o) == dict:
                if v in o:
                    del o[v]
                    v = str(o)\
                        .replace('{', '')\
                        .replace('}', '')\
                        .replace("u'", '')\
                        .replace(' ', '')\
                        .replace("'", '')
                    self.c.execute("UPDATE %s SET %s=? WHERE channel=?" % (TABLE, k), (v, self.channel))
                    self.db.commit()
        elif key == 'channel':
            self.c.execute("DELETE FROM %s WHERE channel=?" % TABLE, (self.channel,))
            self.db.commit()
        else:
            self[key] = ''

    def keys(self):
        if self.r:
            return self.r.keys()
        else:
            return []

    def __repr__(self):
        if self.r:
            return "<Channel object for %s at %s>" % (self.channel, hex(id(self)))
        else:
            return "<Channel object at %s>" % hex(id(self))


def re_to_irc(r, displaying=True):
    if not displaying:
        r = re.sub(r'\.', r'\.', r)
        r = re.sub(r'\*', '.*', r)
    else:
        r = re.sub(r'\\\.', '.', r)
        r = re.sub(r'\.\*', '*', r)
    return r


def op_cmp(user, target):
    if user != 'q' and target == 'q':
        return False
    elif (user != 'a' and user != 'q') and (target == 'a' or target == 'q'):
        return False
    elif (user != 'o' and user != 'a' and user != 'q') \
            and (target == 'o' or target == 'a' or target == 'q'):
        return False
    else:
        return True


def is_op(nick, channel):
    if 'h' in channel.modes and nick in channel.modes['h']:
        return True
    elif 'o' in channel.modes and nick in channel.modes['o']:
        return True
    elif 'a' in channel.modes and nick in channel.modes['a']:
        return True
    elif 'q' in channel.modes and nick in channel.modes['q']:
        return True
    else:
        return False


def secureops(client, channel, c):
    ops = c['operators']
    for user in channel.clients:
        if 'R' not in user.modes or (user.nick not in ops and user.nick != c['owner']):
            if 'q' in channel.modes and user.nick in channel.modes['q']:
                csmode(client, channel, '-q', user.nick)
            if 'a' in channel.modes and user.nick in channel.modes['a']:
                csmode(client, channel, '-a', user.nick)
            if 'o' in channel.modes and user.nick in channel.modes['o']:
                csmode(client, channel, '-o', user.nick)
            if 'h' in channel.modes and user.nick in channel.modes['h']:
                csmode(client, channel, '-h', user.nick)
            if 'v' in channel.modes and user.nick in channel.modes['v']:
                csmode(client, channel, '-v', user.nick)
    csmsg(client, "Enforced SecureOps.")


def restrict(client, channel, c):
    ops = c['operators']
    for user in channel.clients.copy():
        if 'R' not in user.modes or (user.nick not in ops and user.nick != c['owner']):
            for op_list in channel.ops:
                if user.nick in op_list:
                    op_list.remove(user.nick)
            client.broadcast(channel.name, ':%s KICK %s %s :RESTRICTED' % \
                (_cs_ident(), channel.name, user.nick))
            user.channels.pop(channel.name)
            channel.clients.remove(user)
    csmsg(client, "Enforced RESTRICTED.")


def init_channel(client, channel):
    """
    Handle a channel being initialised, or a client joining a registered one.
    """
    c = Channel(channel.name)
    if c.r:
        ops = c['operators']
        protected = c['protected']

        # Succession/Expiration
        db = _db
        cur = db.cursor()
        cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (c['owner'],))
        r = cur.fetchone()
        if not r:
            if c['successor']:
                cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (c['successor'],))
                s = cur.fetchone()
                if s:
                    c['owner'] = c['successor']
                    c['successor'] = ''
                else:
                    del c['channel']
                    return None
            else:
                del c['channel']
                return None
        elif 'R' not in channel.modes:
            csmode(client, channel, '+R')

        # Bans
        if not client.oper and (client.nick != c['owner'] or
                ('R' not in client.modes and client.nick == c['owner'])) and \
                (client.nick not in protected or ('R' not in client.modes and client.nick in protected)):
            bans = c['bans']
            for b in bans.keys():
                if re.match(b, client.client_ident(True)):
                    return ':%s NOTICE %s :Cannot join %s. (Banned)' % \
                        (_cs_ident(), client.nick, channel.name)

        # Restricted
        if not client.oper and c['restricted']:
            if 'R' not in client.modes or (client.nick != c['owner']
                    and client.nick not in ops and client.nick not in protected):
                return ':%s NOTICE %s :Cannot join %s. (Restricted)' % \
                    (_cs_ident(), client.nick, channel.name)

        # Topic/KeepTopic
        if c['topic'] and c['keeptopic'] and not len(channel.clients) \
                and channel.topic != c['topic']:
            channel.topic = c['topic']
            channel.topic_by = c['topic_by']
            channel.topic_time = c['topic_time']

        # Entrymsg
        if c['entrymsg']:
            csmsg(client, "[%s] %s" % (channel.name, c['entrymsg']))

        # MLock
        if c['mlock']:
            for mode, settings in c['modes'].items():
                if ',' in settings:
                    settings = settings.split(',')
                csmode(client, channel, mode, settings)

        # Operators
        if 'o' in channel.supported_modes and client.nick in channel.modes.get('o', []):
            channel.modes['o'].remove(client.nick)
        if 'R' in client.modes and (client.nick == c['owner'] or client.nick == c['successor']):
            c['time_use'] = time.time()
            csmode(client, channel, '+q', client.nick)
        if 'R' in client.modes and client.nick in ops \
                and (client.nick != c['owner'] and client.nick != c['successor']):
            c['time_use'] = time.time()
            csmode(client, channel, '+' + ops[client.nick], client.nick)

    elif 'R' in channel.modes:
        csmode(client, channel, '-R')

    return None


def escape(query):
    return query.replace("'", "")


def csmsg(client, msg):
    client.broadcast(client.nick, ":%s NOTICE %s :%s" % \
        (_cs_ident(), client.nick, msg))


def csmode(client, channel, mode, args=None):
    if isinstance(mode, str):
        mode = [mode]
    for x in mode:
        f = x[0]
        m = x[1:]
        if isinstance(channel, str):
            channel = client.server.channels.get(channel)
        if channel and m in channel.supported_modes:
            if f == '+' and m not in channel.modes:
                channel.modes[m] = []
            if f == '+' and args not in channel.modes.get(m, []):
                if type(args) == list:
                    channel.modes[m].extend(args)
                elif args:
                    channel.modes[m].append(args)
            elif f == '-':
                if args and args in channel.modes.get(m, []):
                    channel.modes[m].remove(args)
                elif m in channel.modes:
                    del channel.modes[m]
            if not args:
                client.broadcast(channel.name, ':%s MODE %s %s' % (_cs_ident(), channel.name, f + m))
            else:
                client.broadcast(channel.name, ':%s MODE %s %s %s' % (_cs_ident(), channel.name, f + m, args))


def fmt_timestamp(ts):
    return datetime.datetime.fromtimestamp(int(ts)).strftime('%b %d %H:%M:%S %Y')


def csmsg_list(client, t):
    for r in t:
        if client.oper:
            ip = " Owner: %s," % r['owner']
        else:
            ip = ''
        chan = client.server.channels.get(r['channel'])
        if chan:
            if 'R' in chan.modes:
                csmsg(client, "\x02\x033%s\x0F:%s Description: %s, Registered: %s" % \
                    (r['channel'], ip, r['description'], fmt_timestamp(r['time_reg'])))
            else:
                csmsg(client, "\x02\x032%s\x0F:%s Description: %s, Registered: %s" % \
                    (r['channel'], ip, r['description'], fmt_timestamp(r['time_reg'])))
        else:
            csmsg(client, "\x02%s\x0F:%s Description: %s, Registered: %s" % \
                (r['channel'], ip, r['description'], fmt_timestamp(r['time_reg'])))
    csmsg(client, "End of \x02LIST\x0F command.")


def is_expired(seconds):
    t = time.time()
    seconds = t - seconds
    minutes, seconds = divmod(seconds, 60)
    hours,   minutes = divmod(minutes, 60)
    days,    hours   = divmod(hours, 24)
    weeks,   days    = divmod(days, 7)
    return MAX_DAYS_UNUSED < days + (weeks * 7)


class CSError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


def _chanserv(ctx):
    """Command handler for /chanserv and /cs."""
    client = ctx.client
    line_body  = ctx.line.body
    raw_params = line_body.split(' ', 1)[1].strip() if ' ' in line_body else ''

    client.last_activity = str(time.time())[:10]
    raw_params = escape(raw_params)
    cmd  = raw_params
    args = ''
    if ' ' in raw_params:
        cmd, args = raw_params.split(' ', 1)
        cmd, args = cmd.lower(), args.lower()
    else:
        cmd = raw_params.lower()

    if cmd == 'help' or not cmd:
        if not args:
            csmsg(client, "\x02/CHANSERV\x0F allows you to register and control various aspects of")
            csmsg(client, "channels. ChanServ can often prevent malicious users from \"taking")
            csmsg(client, "over\" channels by limiting who is allowed channel operator")
            csmsg(client, "privileges. Available commands are listed below; to use them, type")
            csmsg(client, "\x02/CHANSERV \x1Fcommand\x0F. For more information on a specific command,")
            csmsg(client, "type \x02/CHANSERV HELP \x1Fcommand\x0F.")
            csmsg(client, "")
            csmsg(client, "     REGISTER    Register a channel")
            csmsg(client, "     SET         Set channel options and information")
            csmsg(client, "     SOP         Modify the list of SOP users")
            csmsg(client, "     AOP         Modify the list of AOP users")
            csmsg(client, "     HOP         Maintains the HOP (HalfOP) list for a channel")
            csmsg(client, "     VOP         Maintains the VOP (VOiced People) list for a channel")
            csmsg(client, "     DROP        Cancel the registration of a channel")
            csmsg(client, "     BAN         Bans a selected host on a channel")
            csmsg(client, "     UNBAN       Remove ban on a selected host from a channel")
            csmsg(client, "     CLEAR       Tells ChanServ to clear certain settings on a channel")
            csmsg(client, "     OWNER       Gives you owner status on channel")
            csmsg(client, "     DEOWNER     Removes your owner status on a channel")
            csmsg(client, "     PROTECT     Protects a selected nick on a channel")
            csmsg(client, "     DEPROTECT   Deprotects a selected nick on a channel")
            csmsg(client, "     OP          Gives Op status to a selected nick on a channel")
            csmsg(client, "     DEOP        Deops a selected nick on a channel")
            csmsg(client, "     HALFOP      Halfops a selected nick on a channel")
            csmsg(client, "     DEHALFOP    Dehalfops a selected nick on a channel")
            csmsg(client, "     VOICE       Voices a selected nick on a channel")
            csmsg(client, "     DEVOICE     Devoices a selected nick on a channel")
            csmsg(client, "     INVITE      Tells ChanServ to invite you into a channel")
            csmsg(client, "     KICK        Kicks a selected nick from a channel")
            csmsg(client, "     LIST        Lists all registered channels matching a given pattern")
            csmsg(client, "     LOGOUT      This command will logout the selected nickname")
            csmsg(client, "     TOPIC       Manipulate the topic of the specified channel")
            csmsg(client, "     INFO        Lists information about the named registered channel")
            csmsg(client, "     APPENDTOPIC Add text to a channels topic")
            csmsg(client, "     ENFORCE     Enforce various channel modes and set options")
            csmsg(client, "")
            csmsg(client, "Note that any channel which is not used for %i days" % MAX_DAYS_UNUSED)
            csmsg(client, "(i.e. which no user on the channel's access list enters")
            csmsg(client, "for that period of time) will be automatically dropped.")

        elif args == 'register':
            csmsg(client, "Syntax: \x02REGISTER \x1Fchannel\x0F \x02\x1Fpassword\x0F \x02\x1Fdescription\x0F")
            csmsg(client, "")
            csmsg(client, "Registers a channel in the ChanServ database.  In order")
            csmsg(client, "to use this command, you must first be a channel operator")
            csmsg(client, "on the channel you're trying to register.  The password")
            csmsg(client, "is used with the \x02IDENTIFY\x0F command to allow others to")
            csmsg(client, "make changes to the channel settings at a later time.")
            csmsg(client, "The last parameter, which \x02must\x0F be included, is a")
            csmsg(client, "general description of the channel's purpose.")
            csmsg(client, "")
            csmsg(client, "When you register a channel, you are recorded as the")
            csmsg(client, "\"founder\" of the channel.  The channel founder is allowed")
            csmsg(client, "to change all of the channel settings for the channel;")
            csmsg(client, "ChanServ will also automatically give the founder")
            csmsg(client, "channel-operator privileges when s/he enters the channel.")
            csmsg(client, "")
            csmsg(client, "NOTICE: In order to register a channel, you must have")
            csmsg(client, "first registered your nickname.  If you haven't,")
            csmsg(client, "use \x02/NickServ HELP\x0F for information on how to do so.")
            csmsg(client, "")
            csmsg(client, "Note that any channel which is not used for %i days" % MAX_DAYS_UNUSED)
            csmsg(client, "(i.e. which no user on the channel's access list enters")
            csmsg(client, "for that period of time) will be automatically dropped.")

        elif args == 'set':
            csmsg(client, "Syntax: \x02SET \x1Fchannel\x0F \x02\x1Foption\x0F \x02\x1Fparameters\x0F")
            csmsg(client, "")
            csmsg(client, "Allows the channel founder to set various channel options")
            csmsg(client, "and other information.")
            csmsg(client, "")
            csmsg(client, "Available options:")
            csmsg(client, "")
            csmsg(client, "     FOUNDER       Set the founder of a channel")
            csmsg(client, "     SUCCESSOR     Set the successor for a channel")
            csmsg(client, "     PASSWORD      Set the founder password")
            csmsg(client, "     DESC          Set the channel description")
            csmsg(client, "     URL           Associate a URL with the channel")
            csmsg(client, "     EMAIL         Associate an E-mail address with the channel")
            csmsg(client, "     ENTRYMSG      Set a message to be sent to users when they")
            csmsg(client, "                   enter the channel")
            csmsg(client, "     MLOCK         Lock channel modes on or off")
            csmsg(client, "     KEEPTOPIC     Retain topic when channel is not in use")
            csmsg(client, "     PEACE         Regulate the use of critical commands")
            csmsg(client, "     RESTRICTED    Restrict access to the channel")
            csmsg(client, "     SECUREOPS     Stricter control of chanop status")
            csmsg(client, "     SIGNKICK      Sign kicks that are done with KICK command")
            csmsg(client, "     TOPICLOCK     Topic can only be changed with TOPIC")
            csmsg(client, "")
            csmsg(client, "Type \x02/CHANSERV HELP SET \x1Foption\x0F for more information on a")
            csmsg(client, "particular option.")

        elif args == 'drop':
            csmsg(client, "Syntax \x02DROP \x1Fchannel\x0F \x02\x1Fpassword\x0F")
            csmsg(client, "")
            csmsg(client, "Unregisters the named channel ")
            if client.oper:
                csmsg(client, "IRC Operators may supply anything as a password.")

        elif args == 'enforce':
            csmsg(client, "Syntax: \x02ENFORCE \x1Fchannel\x0F \x02\x1Fwhat\x0F")
            csmsg(client, "")
            csmsg(client, "Enforce various channel modes and options.")
            csmsg(client, "Limited to channel Founders and IRC Operators.")

        elif args == 'ban':
            csmsg(client, "Syntax: \x02BAN \x1Fchannel\x0F \x02\x1Fmask\x0F")
            csmsg(client, "")
            csmsg(client, "Bans a selected mask on a channel. Limited to AOPs")
            csmsg(client, "and above, channel owners and IRC Operators.")

        elif args == 'unban':
            csmsg(client, "Syntax: \x02UNBAN \x1Fchannel\x0F \x02\x1Fmask\x0F")
            csmsg(client, "")
            csmsg(client, "Unbans a selected mask from a channel. Limited to AOPs")
            csmsg(client, "and above, channel owners and IRC Operators.")

        elif args == 'protect':
            csmsg(client, "Syntax: \x02PROTECT \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg(client, "")
            csmsg(client, "Protects a registered nick on a channel.")
            csmsg(client, "By default, limited to the founder, SOPs and IRC Operators.")

        elif args == 'deprotect':
            csmsg(client, "Syntax: \x02DEPROTECT \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg(client, "")
            csmsg(client, "Deprotects a selected nick on a channel.")
            csmsg(client, "By default, limited to the founder, SOPs and IRC Operators.")

        else:
            if args:
                csmsg(client, "No help available for \x02%s\x0F." % args)

    elif cmd == 'register':
        if not args or len(args.split()) < 3:
            csmsg(client, "Syntax: \x02/CHANSERV REGISTER \x1Fchannel\x0F \x02\x1Fpassword\x0F \x02\x1Fdescription\x0F")
        elif 'R' not in client.modes:
            csmsg(client, "A registered nickname is required for channel registration.")
        else:
            channel_name, password, description = args.split(' ', 2)
            password = hashlib.sha1(args.encode('utf-8')).hexdigest()
            if not re.match(r'^#([a-zA-Z0-9_])+$', channel_name):
                csmsg(client, "\x02%s\x0F is not a valid channel name.")
            else:
                db = _db
                c = db.cursor()
                c.execute("SELECT * FROM %s WHERE channel=?" % TABLE, (channel_name,))
                r = c.fetchone()
                if r:
                    csmsg(client, "\x02%s\x0F is already registered." % channel_name)
                else:
                    c.execute("SELECT * FROM %s WHERE owner=?" % TABLE, (client.nick,))
                    r = c.fetchall()
                    if len(r) >= MAX_CHANNELS:
                        csmsg(client, "You already have %i channels registered to this nick:" % MAX_CHANNELS)
                        for i in r:
                            csmsg(client, "\x02%s\x0F, %s" % (i['channel'], fmt_timestamp(i['time_reg'])))
                    else:
                        channel = client.channels.get(channel_name)
                        if channel:
                            topic = channel.topic
                            topic_by = channel.topic_by
                            topic_time = channel.topic_time
                        else:
                            topic = topic_by = topic_time = ''
                        t = time.time()
                        db.execute("INSERT INTO %s VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)" % \
                            TABLE, (channel_name, password, description, client.nick, '', '', topic, topic_by,
                                    topic_time, t, t, '', '', '', '', '', '', '', '', '', '', '', '', ''))
                        db.commit()
                        csmsg(client, "Registered \x02%s\x0F to \x02%s\x0F." % (channel_name, client.nick))
                        client.broadcast('umode:W', ':%s NOTICE * :%s has registered the channel \x02%s\x0F.' % \
                            (_cs_ident(), client.nick, channel_name))
                        if channel:
                            client.broadcast(channel_name, ':%s MODE %s +R' % (_cs_ident(), channel_name))

    elif cmd == 'set':
        if not args or len(args.split(' ', 2)) < 3:
            csmsg(client, "Syntax: \x02SET \x1Fchannel\x0F \x02\x1Foption\x0F \x02\x1Fparameters\x0F")
            csmsg(client, "\x02/CHANSERV HELP SET\x0F for more information.")
        else:
            channel_arg = args.split()[0]
            option = args.split()[1]
            params = escape(raw_params.split(' ', 3)[3]) if len(raw_params.split(' ', 3)) > 3 else ''
            c = Channel(channel_arg)
            if 'R' not in client.modes:
                csmsg(client, "Access denied.")
            elif not c.r:
                csmsg(client, "\x02%s\x0F is not a registered channel." % channel_arg)
            else:
                if 'A' not in client.modes and client.nick != c['owner'] and client.nick != c['successor']:
                    csmsg(client, "Access denied.")
                else:
                    if option == 'founder':
                        if 'A' not in client.modes and client.nick != c['owner']:
                            csmsg(client, "Access denied.")
                        else:
                            db = _db
                            cur = db.cursor()
                            cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (params,))
                            r = cur.fetchone()
                            if not r:
                                csmsg(client, "\x02%s\x0F isn't a registered nick." % params)
                            else:
                                c['owner'] = escape(params)
                                csmsg(client, "Founder for %s changed to \x02%s\x0F." % (channel_arg, params))

                    elif option == 'successor':
                        if 'A' not in client.modes and client.nick != c['owner']:
                            csmsg(client, "Access denied.")
                        else:
                            db = _db
                            cur = db.cursor()
                            cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (params,))
                            r = cur.fetchone()
                            if not r:
                                csmsg(client, "\x02%s\x0F isn't a registered nick." % params)
                            else:
                                c['successor'] = escape(params)
                                csmsg(client, "Successor for %s changed to \x02%s\x0F." % (channel_arg, params))

                    elif option == 'password':
                        if 'A' not in client.modes and client.nick != c['owner']:
                            csmsg(client, "Access denied.")
                        else:
                            c['password'] = hashlib.sha1(params.encode('utf-8')).hexdigest()
                            csmsg(client, "Password for %s changed to \x02%s\x0F." % (channel_arg, params))

                    elif option == 'desc':
                        c['description'] = escape(params)
                        csmsg(client, "Description for %s changed to \x02%s\x0F." % (channel_arg, params))

                    elif option == 'url':
                        c['url'] = escape(params)
                        csmsg(client, "URL for %s changed to \x02%s\x0F" % (channel_arg, params))

                    elif option == 'email':
                        if 'A' not in client.modes and client.nick != c['owner']:
                            csmsg(client, "Access denied.")
                        else:
                            c['email'] = escape(params)
                            csmsg(client, "Email address for %s changed to \x02%s\x0F." % (channel_arg, params))

                    elif option == 'entrymsg':
                        if params.lower() == 'off':
                            c['entrymsg'] = ''
                            csmsg(client, "Entry message disabled for %s." % channel_arg)
                        else:
                            c['entrymsg'] = escape(params)
                            csmsg(client, "Entry message for %s changed to \x02%s\x0F." % (channel_arg, params))

                    elif option.lower() in ['mlock', 'keeptopic', 'peace', 'restricted', 'secureops', 'topiclock']:
                        if params.lower() == 'off' and not c[option] or params.lower() == c[option]:
                            csmsg(client, "%s is already \x02%s\x0F for %s." % (option.title(), params.upper(), channel_arg))
                        else:
                            if params.lower() == 'off':
                                if option.lower() == 'mlock':
                                    del c['modes']
                                c[option] = ''
                            else:
                                if option.lower() == 'mlock':
                                    chan = client.server.channels.get(channel_arg)
                                    if not chan:
                                        csmsg(client, "\x02%s\x0F isn't active at the moment. No modes appended." % channel_arg)
                                    else:
                                        for mode, settings in chan.modes.items():
                                            if mode in ['v', 'h', 'o', 'a', 'q', 'b', 'e', 'R']:
                                                continue
                                            if type(settings) == list:
                                                c['modes:+%s' % mode] = ','.join(settings)
                                            elif str(mode) == '+i':
                                                c['modes:+%s' % mode] = ''
                                            elif type(settings) in [str, int, float]:
                                                c['modes:+%s' % mode] = str(settings)
                                        csmsg(client, "The following modes are locked for \x02%s\x0F: %s." % \
                                            (channel_arg, ', '.join(c['modes'].keys())))
                                c[option] = 'on'
                            csmsg(client, "%s for %s set to \x02%s\x0F." % (option.title(), channel_arg, params.upper()))
                    else:
                        csmsg(client, "Unknown option \x02%s\x0F." % option.upper())
                        csmsg(client, "\x02/CHANSERV HELP SET\x0F for more information.")
            del c

    elif cmd == 'enforce':
        if not args or len(args.split()) != 2:
            csmsg(client, "Syntax: \x02ENFORCE \x1Fchannel\x0F \x02\x1Fwhat\x0F")
        else:
            chan, what = args.split()
            what = what.lower()
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if (('R' not in client.modes or client.nick != c['owner']) and not client.oper):
                csmsg(client, "Access denied.")
            elif not c.r:
                csmsg(client, "\x02%s\x0F is not registered." % chan)
            elif not channel:
                csmsg(client, "\x02%s\x0F is not in use." % chan)
            else:
                ops = c['operators']
                if what == 'set':
                    if c['secureops']:
                        secureops(client, channel, c)
                    else:
                        csmsg(client, "Didn't enforce SecureOps.")
                    if c['restricted']:
                        restrict(client, channel, c)
                    else:
                        csmsg(client, "Didn't enforce RESTRICTED.")
                elif what == 'secureops':
                    secureops(client, channel, c)
                elif what == 'restricted':
                    restrict(client, channel, c)
                elif what == 'modes':
                    modes = c['modes']
                    for_removal = []
                    for mode in channel.modes:
                        if '+' + mode not in modes and mode not in ['R', 'n', 't', 'b', 'e', 'v', 'h', 'o', 'a', 'q']:
                            for_removal.append('-' + mode)
                    for mode in for_removal:
                        csmode(client, channel, mode)
                    for mode, settings in c['modes'].items():
                        if mode[1:] not in channel.modes:
                            if ',' in settings:
                                settings = settings.split(',')
                            csmode(client, channel, mode, settings)
                    if modes:
                        csmsg(client, "Enforced \x02%s\x0F on \x02%s\x0F." % (', '.join(modes.keys()), channel.name))
                    else:
                        csmsg(client, "Enforced modes.")
                else:
                    csmsg(client, "Unknown option \x02%s\x0F." % what)

    elif cmd == 'sop':
        if not args or len(args.split()) < 2 or args.split()[1].lower() not in ['add', 'del', 'list', 'clear']:
            csmsg(client, "Syntax: \x02SOP \x1Fchannel\x0F \x02{ADD|DEL|LIST|CLEAR} [\x1Fnick\x0F\x02]\x0F")
            csmsg(client, "\x02/CHANSERV HELP SOP\x0F for more information.")
        else:
            chan, params_rest = args.split(' ', 1)
            params_list = params_rest.split()
            c = Channel(chan)
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif ('R' not in client.modes or client.nick != c['owner']) and not client.oper:
                csmsg(client, "Access denied.")
            else:
                if params_list[0].lower() in ['add', 'del']:
                    nick = params_list[1]
                    db = _db
                    cur = db.cursor()
                    cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (nick,))
                    r = cur.fetchone()
                    if not r:
                        csmsg(client, "Channel SOP lists may only contain registered nicknames.")
                    elif params_list[0].lower() == 'add':
                        c['operators:%s' % nick] = 'a'
                        csmsg(client, "\x02%s\x0F added to %s SOP list." % (nick, chan))
                    elif params_list[0].lower() == 'del':
                        ops = c['operators']
                        if nick not in ops or (nick in ops and ops[nick] != 'a'):
                            csmsg(client, "\x02%s\x0F is not in the SOP list for %s." % (nick, chan))
                        else:
                            del c['operators:%s' % nick]
                            csmsg(client, "Removed \x02%s\x0F from %s SOP list." % (nick, chan))
                elif params_list[0].lower() == 'list':
                    ops = c['operators']
                    lst = [i for i in ops.items() if i[1] == 'a']
                    for x in lst:
                        csmsg(client, "\x02%s\x0F" % x[0])
                    csmsg(client, "End of %s SOP list." % chan)
                elif params_list[0].lower() == 'clear':
                    ops = c['operators']
                    lst = [i for i in ops.items() if i[1] == 'a']
                    for x in lst:
                        del c['operators:%s' % x[0]]
                    csmsg(client, "Cleared %s SOP list." % chan)

    elif cmd == 'aop':
        if not args or len(args.split()) < 2 or args.split()[1].lower() not in ['add', 'del', 'list', 'clear']:
            csmsg(client, "Syntax: \x02AOP \x1Fchannel\x0F \x02{ADD|DEL|LIST|CLEAR} [\x1Fnick\x0F\x02]\x0F")
            csmsg(client, "\x02/CHANSERV HELP AOP\x0F for more information.")
        else:
            chan, params_rest = args.split(' ', 1)
            params_list = params_rest.split()
            c = Channel(chan)
            ops = c['operators'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif (('R' not in client.modes or client.nick != c['owner']) and not client.oper) \
                    and (client.nick not in ops or (client.nick in ops and (ops[client.nick] != 'a' and ops[client.nick] != 'q'))):
                csmsg(client, "Access denied.")
            else:
                if params_list[0].lower() in ['add', 'del']:
                    nick = params_list[1]
                    db = _db
                    cur = db.cursor()
                    cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (nick,))
                    r = cur.fetchone()
                    if not r:
                        csmsg(client, "Channel AOP lists may only contain registered nicknames.")
                    elif params_list[0].lower() == 'add':
                        c['operators:%s' % nick] = 'o'
                        csmsg(client, "\x02%s\x0F added to %s AOP list." % (nick, chan))
                    elif params_list[0].lower() == 'del':
                        ops = c['operators']
                        if nick not in ops or (nick in ops and ops[nick] != 'o'):
                            csmsg(client, "\x02%s\x0F is not in the AOP list for %s." % (nick, chan))
                        else:
                            del c['operators:%s' % nick]
                            csmsg(client, "Removed \x02%s\x0F from %s AOP list." % (nick, chan))
                elif params_list[0].lower() == 'list':
                    lst = [i for i in ops.items() if i[1] == 'o']
                    for x in lst:
                        csmsg(client, "\x02%s\x0F" % x[0])
                    csmsg(client, "End of %s AOP list." % chan)
                elif params_list[0].lower() == 'clear':
                    ops = c['operators']
                    lst = [i for i in ops.items() if i[1] == 'o']
                    for x in lst:
                        del c['operators:%s' % x[0]]
                    csmsg(client, "Cleared %s AOP list." % chan)

    elif cmd == 'hop':
        if not args or len(args.split()) < 2 or args.split()[1].lower() not in ['add', 'del', 'list', 'clear']:
            csmsg(client, "Syntax: \x02HOP \x1Fchannel\x0F \x02{ADD|DEL|LIST|CLEAR} [\x1Fnick\x0F\x02]\x0F")
            csmsg(client, "\x02/CHANSERV HELP HOP\x0F for more information.")
        else:
            chan, params_rest = args.split(' ', 1)
            params_list = params_rest.split()
            c = Channel(chan)
            ops = c['operators'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif (('R' not in client.modes or client.nick != c['owner']) and not client.oper) \
                    and (client.nick not in ops or (client.nick in ops
                    and (ops[client.nick] != 'o' and ops[client.nick] != 'a' and ops[client.nick] != 'q'))):
                csmsg(client, "Access denied.")
            else:
                if params_list[0].lower() in ['add', 'del']:
                    nick = params_list[1]
                    db = _db
                    cur = db.cursor()
                    cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (nick,))
                    r = cur.fetchone()
                    if not r:
                        csmsg(client, "Channel HOP lists may only contain registered nicknames.")
                    elif params_list[0].lower() == 'add':
                        c['operators:%s' % nick] = 'h'
                        csmsg(client, "\x02%s\x0F added to %s HOP list." % (nick, chan))
                    elif params_list[0].lower() == 'del':
                        ops = c['operators']
                        if nick not in ops or (nick in ops and ops[nick] != 'h'):
                            csmsg(client, "\x02%s\x0F is not in the HOP list for %s." % (nick, chan))
                        else:
                            del c['operators:%s' % nick]
                            csmsg(client, "Removed \x02%s\x0F from %s HOP list." % (nick, chan))
                elif params_list[0].lower() == 'list':
                    lst = [i for i in ops.items() if i[1] == 'h']
                    for x in lst:
                        csmsg(client, "\x02%s\x0F" % x[0])
                    csmsg(client, "End of %s HOP list." % chan)
                elif params_list[0].lower() == 'clear':
                    ops = c['operators']
                    lst = [i for i in ops.items() if i[1] == 'h']
                    for x in lst:
                        del c['operators:%s' % x[0]]
                    csmsg(client, "Cleared %s HOP list." % chan)

    elif cmd == 'vop':
        if not args or len(args.split()) < 2 or args.split()[1].lower() not in ['add', 'del', 'list', 'clear']:
            csmsg(client, "Syntax: \x02VOP \x1Fchannel\x0F \x02{ADD|DEL|LIST|CLEAR} [\x1Fnick\x0F\x02]\x0F")
            csmsg(client, "\x02/CHANSERV HELP VOP\x0F for more information.")
        else:
            chan, params_rest = args.split(' ', 1)
            params_list = params_rest.split()
            c = Channel(chan)
            ops = c['operators'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif (('R' not in client.modes or client.nick != c['owner']) and not client.oper) \
                    and (client.nick not in ops or (client.nick in ops
                    and (ops[client.nick] != 'o' and ops[client.nick] != 'a' and ops[client.nick] != 'q'))):
                csmsg(client, "Access denied.")
            else:
                if params_list[0].lower() in ['add', 'del']:
                    nick = params_list[1]
                    db = _db
                    cur = db.cursor()
                    cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (nick,))
                    r = cur.fetchone()
                    if not r:
                        csmsg(client, "Channel VOP lists may only contain registered nicknames.")
                    elif params_list[0].lower() == 'add':
                        c['operators:%s' % nick] = 'v'
                        csmsg(client, "\x02%s\x0F added to %s VOP list." % (nick, chan))
                    elif params_list[0].lower() == 'del':
                        ops = c['operators']
                        if nick not in ops or (nick in ops and ops[nick] != 'v'):
                            csmsg(client, "\x02%s\x0F is not in the VOP list for %s." % (nick, chan))
                        else:
                            del c['operators:%s' % nick]
                            csmsg(client, "Removed \x02%s\x0F from %s VOP list." % (nick, chan))
                elif params_list[0].lower() == 'list':
                    lst = [i for i in ops.items() if i[1] == 'v']
                    for x in lst:
                        csmsg(client, "\x02%s\x0F" % x[0])
                    csmsg(client, "End of %s VOP list." % chan)
                elif params_list[0].lower() == 'clear':
                    ops = c['operators']
                    lst = [i for i in ops.items() if i[1] == 'v']
                    for x in lst:
                        del c['operators:%s' % x[0]]
                    csmsg(client, "Cleared %s VOP list." % chan)

    elif cmd == 'ban':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax: \x02/CHANSERV BAN \x1F#channel\x0F \x02\x1Fmask\x0F")
        else:
            chan, mask = args.split(' ', 1)
            chan = escape(chan)
            mask = escape(mask)
            if '!' not in mask and '@' not in mask:
                mask += '!*@*'
            c = Channel(chan)
            if not c.r:
                csmsg(client, "\x02%s\x0F isn't registered." % chan)
            else:
                o = c['operators']
                if not client.oper and ('R' not in client.modes or client.nick != c['owner']) \
                        and (client.nick not in o or (client.nick in o and (o[client.nick] == 'v' or o[client.nick] == 'h'))):
                    csmsg(client, "Access denied.")
                else:
                    b = c['bans']
                    m = re_to_irc(mask, False)
                    if m in b:
                        csmsg(client, "\x02%s\x0F is already banned from %s." % (mask, chan))
                    else:
                        c['bans:%s' % m] = client.nick
                        csmsg(client, "Banned \x02%s\x0F from %s." % (mask, chan))

    elif cmd == 'unban':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax: \x02/CHANSERV UNBAN \x1F#channel\x0F \x02\x1Fmask\x0F")
        else:
            chan, mask = args.split(' ', 1)
            chan = escape(chan)
            mask = escape(mask)
            if '!' not in mask and '@' not in mask:
                mask += '!*@*'
            c = Channel(chan)
            if not c.r:
                csmsg(client, "\x02%s\x0F isn't registered." % chan)
            else:
                o = c['operators']
                if not client.oper and ('R' not in client.modes or client.nick != c['owner']) \
                        and (client.nick not in o or (client.nick in o and (o[client.nick] == 'v' or o[client.nick] == 'h'))):
                    csmsg(client, "Access denied.")
                else:
                    b = c['bans']
                    m = re_to_irc(mask, False)
                    if m not in b:
                        csmsg(client, "\x02%s\x0F isn't banned from %s." % (mask, chan))
                    else:
                        del c['bans:%s' % m]
                        csmsg(client, "Unbanned \x02%s\x0F from %s." % (mask, chan))

    elif cmd == 'clear':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax: \x02CLEAR \x1Fchannel\x0F \x02\x1Fwhat\x0F")
        else:
            chan, what = args.split(' ', 1)
            what = what.lower()
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif not channel:
                csmsg(client, "%s is not currently in use." % chan)
            elif (client.nick != c['owner'] or 'R' not in client.modes) and not client.oper:
                csmsg(client, "Access denied.")
            else:
                if what == 'modes':
                    modes = channel.modes.copy()
                    [csmode(client, channel, '-' + mode) for mode in modes
                     if mode not in ['n', 't', 'R', 'e', 'b', 'v', 'h', 'o', 'a', 'q']]
                    csmsg(client, "Modes reset for \x02%s\x0F." % chan)
                elif what == 'bans':
                    if 'b' in channel.modes:
                        channel.modes['b'] = []
                        csmsg(client, "Bans cleared for \x02%s\x0F." % chan)
                elif what == 'excepts':
                    if 'e' in channel.modes:
                        channel.modes['e'] = []
                        csmsg(client, "Excepts cleared for \x02%s\x0F." % chan)
                elif what == 'ops':
                    if 'o' in channel.modes and len(channel.modes['o']) > 0:
                        for nick in channel.modes['o']:
                            csmode(client, channel, '-o', nick)
                        csmsg(client, "Cleared Operators list on \x02%s\x0F" % chan)
                elif what == 'hops':
                    if 'h' in channel.modes and len(channel.modes['h']) > 0:
                        for nick in channel.modes['h']:
                            csmode(client, channel, '-h', nick)
                        csmsg(client, "Cleared Half-Operators list on \x02%s\x0F" % chan)
                elif what == 'voices':
                    if 'v' in channel.modes and len(channel.modes['v']) > 0:
                        for nick in channel.modes['v']:
                            csmode(client, channel, '-v', nick)
                        csmsg(client, "Cleared Voiced People on \x02%s\x0F" % chan)
                elif what == 'users':
                    protected = c['protected']
                    for user in channel.clients.copy():
                        if 'Q' in user.modes or ('R' in user.modes and user.nick == c['owner']) \
                                or ('R' in user.modes and user.nick in protected):
                            continue
                        client.broadcast(channel.name, ':%s KICK %s %s :CLEAR USERS used by %s.' % \
                            (_cs_ident(), channel.name, user.nick, client.nick))
                        for op_list in channel.ops:
                            if user.nick in op_list:
                                op_list.remove(user.nick)
                        user.channels.pop(channel.name)
                        channel.clients.remove(user)
                    if not len(channel.clients):
                        client.server.channels.pop(channel.name)
                    csmsg(client, "Cleared users from \x02%s\x0F." % chan)
                else:
                    csmsg(client, "Unknown setting \x02%s\x0F." % what)

    elif cmd == 'owner':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax \x02OWNER \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ', 1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            ops = c['operators'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif not channel:
                csmsg(client, "%s is not currently in use." % chan)
            elif client.nick != c['owner'] or 'R' not in client.modes:
                csmsg(client, "Access denied.")
            elif nick in channel.modes.get('q', []):
                csmsg(client, "%s is already an owner in %s." % (nick, chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(client, channel, '+q', nick)
                    csmsg(client, "Owner status given to %s in %s." % (nick, chan))
                else:
                    csmsg(client, "%s is not on %s." % (nick, chan))

    elif cmd == 'deowner':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax \x02DEOWNER \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ', 1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif not channel:
                csmsg(client, "%s is not currently in use." % chan)
            elif client.nick != c['owner'] or 'R' not in client.modes:
                csmsg(client, "Access denied.")
            elif nick not in channel.modes.get('q', []):
                csmsg(client, "%s is not an owner in %s." % (nick, chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(client, channel, '-q', nick)
                    csmsg(client, "Owner status removed from %s in %s." % (nick, chan))
                else:
                    csmsg(client, "%s is not on %s." % (nick, chan))

    elif cmd == 'protect':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax \x02PROTECT \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ', 1)
            c = Channel(chan)
            ops = c['operators'] if c.r else {}
            protected = c['protected'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif 'R' not in client.modes and not client.oper:
                csmsg(client, "Access denied.")
            elif (client.nick not in ops and client.nick != c['owner']) \
                    or (client.nick in ops and ops[client.nick] != 'a') and not client.oper:
                csmsg(client, "Access denied.")
            elif nick in protected:
                csmsg(client, "%s is already protected in \x02%s\x0F." % (nick, chan))
            else:
                db = _db
                cur = db.cursor()
                cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (nick,))
                r = cur.fetchone()
                if not r:
                    csmsg(client, "\x02%s\x0F isn't registered." % nick)
                else:
                    c['protected:%s' % nick] = client.nick
                    csmsg(client, "Protected %s in \x02%s\x0F." % (nick, chan))

    elif cmd == 'deprotect':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax \x02DEPROTECT \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ', 1)
            c = Channel(chan)
            ops = c['operators'] if c.r else {}
            protected = c['protected'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif 'R' not in client.modes and not client.oper:
                csmsg(client, "Access denied.")
            elif (client.nick not in ops and client.nick != c['owner']) \
                    or (client.nick in ops and ops[client.nick] != 'a') and not client.oper:
                csmsg(client, "Access denied.")
            elif nick not in protected:
                csmsg(client, "%s isn't in the list of protected users for \x02%s\x0F." % (nick, chan))
            else:
                del c['protected:%s' % nick]
                csmsg(client, "Removed %s from the list of protected users for \x02%s\x0F." % (nick, chan))

    elif cmd == 'op':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax \x02OP \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ', 1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            ops = c['operators'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif not channel:
                csmsg(client, "%s is not currently in use." % chan)
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg(client, "Access denied.")
            elif c['owner'] != client.nick and client.nick in ops \
                    and (ops[client.nick] == 'v' or ops[client.nick] == 'h'):
                csmsg(client, "Access denied.")
            elif nick in channel.modes.get('o', []):
                csmsg(client, "%s is already an operator in %s." % (nick, chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(client, channel, '+o', nick)
                    csmsg(client, "Operator status given to %s in %s." % (nick, chan))
                else:
                    csmsg(client, "%s is not on %s." % (nick, chan))

    elif cmd == 'deop':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax \x02DEOP \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ', 1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            ops = c['operators'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif not channel:
                csmsg(client, "%s is not currently in use." % chan)
            elif 'R' not in client.modes:
                csmsg(client, "Access denied. (Must be identified with services.)")
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg(client, "Access denied.")
            elif client.nick in ops and (ops[client.nick] == 'v' or ops[client.nick] == 'h') \
                    and c['owner'] != client.nick:
                csmsg(client, "Access denied.")
            elif nick not in channel.modes.get('o', []):
                csmsg(client, "%s isn't an operator in %s." % (nick, chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(client, channel, '-o', nick)
                    csmsg(client, "Removed operator status from %s in %s." % (nick, chan))
                else:
                    csmsg(client, "%s is not on %s." % (nick, chan))

    elif cmd == 'halfop':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax \x02HALFOP \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ', 1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            ops = c['operators'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif not channel:
                csmsg(client, "%s is not currently in use." % chan)
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg(client, "Access denied.")
            elif c['owner'] != client.nick and client.nick in ops \
                    and (ops[client.nick] == 'v' or ops[client.nick] == 'h'):
                csmsg(client, "Access denied.")
            elif nick in channel.modes.get('h', []):
                csmsg(client, "%s is already a half-operator in %s." % (nick, chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(client, channel, '+h', nick)
                    csmsg(client, "Half Operator status given to %s in %s." % (nick, chan))
                else:
                    csmsg(client, "%s is not on %s." % (nick, chan))

    elif cmd == 'dehalfop':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax \x02DEHALFOP \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ', 1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            ops = c['operators'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif not channel:
                csmsg(client, "%s is not currently in use." % chan)
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg(client, "Access denied.")
            elif c['owner'] != client.nick and client.nick in ops \
                    and (ops[client.nick] == 'v' or ops[client.nick] == 'h'):
                csmsg(client, "Access denied.")
            elif nick not in channel.modes.get('h', []):
                csmsg(client, "%s isn't a half-operator in %s." % (nick, chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(client, channel, '-h', nick)
                    csmsg(client, "Removed half operator status from %s in %s." % (nick, chan))
                else:
                    csmsg(client, "%s is not on %s." % (nick, chan))

    elif cmd == 'voice':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax \x02VOICE \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ', 1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            ops = c['operators'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif not channel:
                csmsg(client, "%s is not currently in use." % chan)
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg(client, "Access denied.")
            elif client.nick in ops and ops[client.nick] == 'v' and c['owner'] != client.nick:
                csmsg(client, "Access denied.")
            elif nick in channel.modes.get('v', []):
                csmsg(client, "%s is already voiced in %s." % (nick, chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(client, channel, '+v', nick)
                    csmsg(client, "Voice given to %s in %s." % (nick, chan))
                else:
                    csmsg(client, "%s is not on %s." % (nick, chan))

    elif cmd == 'devoice':
        if not args or len(args.split(' ', 1)) != 2:
            csmsg(client, "Syntax \x02DEVOICE \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ', 1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            ops = c['operators'] if c.r else {}
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif not channel:
                csmsg(client, "%s is not currently in use." % chan)
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg(client, "Access denied.")
            elif client.nick in ops and ops[client.nick] == 'v' and c['owner'] != client.nick:
                csmsg(client, "Access denied.")
            elif nick not in channel.modes.get('v', []):
                csmsg(client, "%s isn't voiced in %s." % (nick, chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(client, channel, '-v', nick)
                    csmsg(client, "Voice removed from %s in %s." % (nick, chan))
                else:
                    csmsg(client, "%s is not on %s." % (nick, chan))

    elif cmd == 'invite':
        if not args:
            csmsg(client, "Syntax: \x02/CHANSERV INVITE \x1Fchannel\x0F")
        elif 'R' not in client.modes:
            csmsg(client, "Access denied.")
        else:
            c = Channel(args)
            channel = client.server.channels.get(args)
            if not c.r or not channel:
                csmsg(client, "Channel \x02%s\x0F doesn't exist" % args)
            elif 'i' not in channel.modes:
                csmsg(client, "\x02%s\x0F is not +i." % args)
            else:
                o = c['operators']
                if client.nick != c['owner'] and client.nick != c['successor'] and \
                        (client.nick not in o or (client.nick in o and o[client.nick] == 'v')):
                    csmsg(client, "Access denied.")
                elif 'i' in channel.modes and type(channel.modes['i']) == list:
                    channel.modes['i'].append(client.nick)
                    response = ':%s NOTICE @%s :%s invited %s into the channel.' % \
                        (_cs_ident(), channel.name, _cs_ident().split('!')[0], client.nick)
                    client.broadcast(channel.name, response)
                    response = ':%s INVITE %s :%s' % (_cs_ident(), client.nick, channel.name)
                    client.broadcast(client.nick, response)

    elif cmd == 'kick':
        if not args or ' ' not in args or len(args.split(' ', 2)) != 3:
            csmsg(client, "Usage: \x02/CHANSERV KICK \x1Fchannel\x0F \x02\x1Fnick\x0F \x02\x1Freason\x0F")
        else:
            channel_name, nick, reason = args.split(' ', 2)
            c = Channel(channel_name)
            if not c.r:
                csmsg(client, "\x02%s\x0F isn't registered." % channel_name)
            else:
                channel = client.server.channels.get(channel_name)
                if not channel:
                    csmsg(client, "%s no such channel." % channel_name)
                else:
                    chanops = c['operators']
                    if 'R' not in client.modes:
                        csmsg(client, "Access denied. (Must be identified with services.)")
                    elif client.nick != c['owner'] and client.nick not in chanops:
                        csmsg(client, "Access denied.")
                    elif client.nick in chanops and chanops[client.nick] == 'v':
                        csmsg(client, "Access denied.")
                    elif c['peace']:
                        csmsg(client, "Access denied. (Peace.)")
                    else:
                        user = None
                        for i in channel.clients:
                            if i.nick == nick:
                                user = i
                                break
                        if not user:
                            csmsg(client, "\x02%s\x0F is not currently on channel %s" % (nick, channel_name))
                        else:
                            if 'Q' in user.modes:
                                csmsg(client, "Cannot kick %s. (+Q)" % nick)
                            else:
                                for op_list in channel.ops:
                                    if user.nick in op_list:
                                        op_list.remove(user.nick)
                                if c['signkick']:
                                    client.broadcast(channel.name, ':%s KICK %s %s :%s (%s)' % \
                                        (_cs_ident(), channel.name, user.nick, reason, client.nick))
                                else:
                                    client.broadcast(channel.name, ':%s KICK %s %s :%s' % \
                                        (_cs_ident(), channel.name, user.nick, reason))
                                user.channels.pop(channel.name)
                                channel.clients.remove(user)
            del c

    elif cmd in ('topic', 'appendtopic'):
        if not args or len(args.split(' ', 1)) < 2:
            csmsg(client, "Usage: \x02/CHANSERV TOPIC \x1Fchannel\x0F \x02\x1Ftopic\x0F")
        else:
            chan = args.split()[0]
            topic = raw_params.split(' ', 2)[2] if len(raw_params.split(' ', 2)) > 2 else ''
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if not c.r:
                csmsg(client, "%s isn't registered." % chan)
            elif c['topiclock'] == 'on' and client.nick != c['owner']:
                csmsg(client, "Topic of %s is locked." % chan)
            else:
                ops = c['operators']
                if client.nick not in ops and client.nick != c['owner'] and client.nick != c['successor']:
                    csmsg(client, "You are not a channel operator.")
                elif client.nick in ops and ops[client.nick] == 'v':
                    csmsg(client, "You are not a channel operator.")
                else:
                    if cmd == 'appendtopic':
                        if channel and channel.topic:
                            topic = '%s %s' % (channel.topic, topic)
                        elif c['topic']:
                            topic = '%s %s' % (c['topic'], topic)
                    if topic != c['topic']:
                        c['topic'] = topic
                        c['topic_by'] = client.nick
                        c['topic_time'] = str(time.time())[:10]
                        if not channel:
                            csmsg(client, "Stored topic for %s changed to \x02%s\x0F." % (chan, topic))
                    if channel and channel.topic != topic:
                        channel.topic = topic
                        channel.topic_time = str(time.time())[:10]
                        client.broadcast(channel.name, ':%s TOPIC %s :%s' % (_cs_ident(), chan, topic))
                        csmsg(client, "Topic of %s changed to \x02%s\x0F" % (chan, topic))
            del c

    elif cmd == 'list':
        if not args:
            csmsg(client, "Usage \x02/CHANSERV LIST \x1Fpattern\x0F")
        else:
            if not client.oper or 'R' not in client.modes:
                csmsg(client, "Access denied.")
            else:
                if not args.startswith('#') and not args.startswith('*'):
                    args = '#' + args
                args = escape(args.replace('*', '%'))
                db = _db
                c = db.cursor()
                c.execute("SELECT * FROM %s WHERE channel LIKE ?" % TABLE, (args,))
                t = c.fetchall()
                csmsg_list(client, t)

    elif cmd == 'info':
        if not args:
            csmsg(client, "Usage: \x02/CHANSERV INFO \x1FCHANNEL\x0F")
        else:
            c = Channel(escape(args))
            if not c.r:
                csmsg(client, "\x02%s\x0F isn't registered." % args)
            else:
                channel = client.server.channels.get(args)
                bans = list(c['bans'].items())
                ops = c['operators']
                if channel:
                    csmsg(client, " \x02%s\x0F is active with %i client(s)" % (args, len(channel.clients)))
                else:
                    csmsg(client, "\x02%s\x0F:" % args)
                if c['url']:
                    csmsg(client, "            URL: %s" % c['url'])
                if channel:
                    csmsg(client, "          Topic: %s" % channel.topic)
                csmsg(client, "          About: %s" % c['description'])
                if client.oper and c['email']:
                    csmsg(client, "         E-Mail: \x02%s\x0F" % c['email'])
                if client.oper or 'R' in client.modes:
                    csmsg(client, "        Founder: %s" % c['owner'])
                csmsg(client, "      Last used: %s" % fmt_timestamp(c['time_use']))
                csmsg(client, "Time registered: %s" % fmt_timestamp(c['time_reg']))
                if bans:
                    if client.oper or ('R' in client.modes and client.nick == c['owner']) \
                            or ('R' in client.modes and client.nick in ops and ops[client.nick] != 'v'):
                        l = max([len(re_to_irc(i[0])) for i in bans])
                        csmsg(client, "           Bans: \x02%s\x0F %s(%s)" % \
                            (re_to_irc(bans[0][0]), ' ' * int(l - len(re_to_irc(bans[0][0]))), bans[0][1]))
                        for index, (mask, setter) in enumerate(bans):
                            if index == 0:
                                continue
                            mask = re_to_irc(mask)
                            csmsg(client, ' ' * 17 + '\x02%s\x0F %s(%s)' % (mask, ' ' * int(l - len(mask)), setter))
            del c

    elif cmd == 'drop':
        if not args or ' ' not in args:
            csmsg(client, "Usage: \x02/CHANSERV DROP \x1Fchannel\x0F \x02\x1Fpassword\x0F")
        else:
            channel_name, password = args.split()
            password = hashlib.sha1(password.encode('utf-8')).hexdigest()
            db = _db
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE channel=?" % TABLE, (channel_name,))
            r = c.fetchone()
            if not r:
                csmsg(client, "\x02%s\x0F isn't registered." % channel_name)
            else:
                if client.oper or (r['password'] == password):
                    c.execute("DELETE FROM %s WHERE channel=?" % TABLE, (channel_name,))
                    db.commit()
                    csmsg(client, "Dropped \x02%s\x0F." % channel_name)
                    client.broadcast('umode:W', ':%s NOTICE * :%s has dropped the channel \x02%s\x0F.' % \
                        (_cs_ident(), client.nick, channel_name))
                    channel = client.server.channels.get(channel_name)
                    if channel and 'R' in channel.modes:
                        del channel.modes['R']
                        client.broadcast(channel_name, ":%s MODE %s -R" % (_cs_ident(), channel_name))
                else:
                    csmsg(client, "Incorrect password.")
                    warn = ":%s NOTICE * :\x034WARNING\x0F :%s tried to drop %s with an incorrect password." % \
                        (_cs_ident(), client.nick, channel_name)
                    client.broadcast('umode:W', warn)

    elif cmd == "expire":
        if not client.oper:
            csmsg(client, "Unknown command.")
            csmsg(client, "Use \x02/CHANSERV HELP\x0F for a list of available commands.")
        else:
            db = _db
            c = db.cursor()
            c.execute("SELECT * FROM %s" % TABLE)
            t = c.fetchall()
            for r in t:
                if is_expired(r['time_use']):
                    csmsg(client, "\x02%s\x0F has expired due to inactivity." % r['channel'])
                    client.broadcast('umode:W', ':%s NOTICE * :%s expired \x02%s\x0F.' % \
                        (_cs_ident(), client.nick, r['channel']))
                    c.execute("DELETE FROM %s WHERE channel=?" % TABLE, (r['channel'],))
            db.commit()
            csmsg(client, "All registrations have been cycled through.")

    elif cmd == "xyzzy":
        c = Channel(args)
        if c.r and client.oper:
            csmsg(client, str(c))
            for i in c.keys():
                csmsg(client, '%s: %s' % (i, c[i]))
            csmsg(client, "")
        csmsg(client, "Nothing happens.")
        if c.r and client.oper:
            csmsg(client, "")
        del c

    else:
        csmsg(client, "Unknown command.")
        csmsg(client, "Use \x02/CHANSERV HELP\x0F for a list of available commands.")


def cmode_R(ctx):
    """
    Invoked on new channel creation (new=True) and when any command is issued
    in a channel with mode +R active (func interception).
    """
    client  = ctx.client
    channel = ctx.get('channel')

    if channel is None:
        return

    if ctx.get('new'):
        # New channel created: initialise registration state.
        cancel = init_channel(client, channel)
        if cancel:
            ctx["cancel"] = cancel
        return

    func    = ctx.get('func')
    params  = ctx.get('params', '')

    if func is None:
        return

    c = Channel(channel.name)
    if not c.r:
        if 'R' in channel.modes:
            csmode(client, channel, '-R')
        return

    if func.__name__ == 'handle_join':
        cancel = init_channel(client, channel)
        if cancel:
            ctx["cancel"] = cancel

    elif func.__name__ == 'handle_topic':
        if client.oper or is_op(client.nick, channel):
            if c['topiclock']:
                ctx["cancel"] = ':%s NOTICE %s :Topic locked for %s.' % \
                    (_cs_ident(), client.nick, channel.name)
            elif ':' in params and is_op(client.nick, channel):
                c['topic'] = params.split(':')[1]
                c['topic_by'] = client.nick
                c['topic_time'] = str(time.time())[:10]

    elif func.__name__ == 'handle_kick':
        target_nick = params.split()[1] if len(params.split()) > 1 else ''
        if target_nick == c['owner']:
            params_list = params.split()
            user = client.server.clients.get(params_list[1])
            if user and 'R' in user.modes and user in channel.clients:
                params_list[1:] = ['_']
                ctx["params"] = ' '.join(params_list)
                csmsg(client, "Cannot kick channel Founder.")
        elif c['peace']:
            if not client.oper and (client.nick != c['owner'] or 'R' not in client.modes):
                ctx["cancel"] = ':%s NOTICE %s :Cannot use KICK in \x02%s\x0F. (Peace)' % \
                    (_cs_ident(), client.nick, channel.name)
        elif len(params.split()) > 1 and params.split()[1] in c['protected']:
            user = client.server.clients.get(params.split()[1])
            if user and 'R' in user.modes:
                ctx["cancel"] = ':%s NOTICE %s :Cannot kick protected user \x02%s\x0F from \x02%s\x0F.' % \
                    (_cs_ident(), client.nick, user.nick, channel.name)

    elif func.__name__ == 'handle_mode':
        if c['mlock'] and not client.oper and (client.nick != c['owner']
                or (client.nick == c['owner'] and 'R' not in client.modes)):
            ctx["cancel"] = ':%s NOTICE %s :Modes are locked for \x02%s\x0F.' % \
                (_cs_ident(), client.nick, channel.name)
        elif not client.oper and (c['secureops'] or c['peace'] or c['protected']) \
                and is_op(client.nick, channel):
            target = ''
            mode = params.split(' ', 1)[1] if ' ' in params else ''
            if ' ' in mode:
                mode, target = mode.split(' ', 1)
            if mode[1:] in ['v', 'h', 'o', 'a', 'q']:
                target_user = client.server.clients.get(target)
                ops = c['operators']
                if c['secureops']:
                    if target_user and target_user.nick not in ops:
                        ctx["cancel"] = ':%s NOTICE %s :\x02%s\x0F is not in any of the access lists for \x02%s\x0F. (SecureOps)' % \
                            (_cs_ident(), client.nick, target_user.nick, channel.name)
                    elif target_user and 'R' not in target_user.modes:
                        ctx["cancel"] = ':%s NOTICE %s :\x02%s\x0F is not identified with services. (SecureOps)' % \
                            (_cs_ident(), client.nick, target_user.nick)
                elif (c['peace'] and mode[0] == '-') and ('R' not in client.modes or client.nick != c['owner']):
                    ctx["cancel"] = ':%s NOTICE %s :Cannot revoke privileges on \x02%s\x0F. (Peace)' % \
                        (_cs_ident(), client.nick, channel.name)
                elif mode[0] == '-' and target_user and target_user.nick in c['protected'] \
                        and 'R' in target_user.modes:
                    ctx["cancel"] = ':%s NOTICE %s :Cannot revoke privileges on \x02%s\x0F from protected user \x02%s\x0F.' % \
                        (_cs_ident(), client.nick, channel.name, target_user.nick)

    del c


def __init__(ctx):
    global _db, _srv_domain
    for pkg in __package__:
        if pkg["name"] in ("chanserv", "cs"):
            pkg["callable"] = _chanserv
        elif pkg["name"] == "R":
            pkg["callable"] = cmode_R

    if hasattr(ctx, 'server') and ctx.server:
        _srv_domain = ctx.server.config.server.domain

    if _db is None:
        import sqlite3
        db = sqlite3.connect(DB_FILE, check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute(
            "CREATE TABLE IF NOT EXISTS %s "
            "(channel, password, description, owner, operators, bans, topic, topic_by, topic_time, "
            "time_reg REAL, time_use REAL, successor, url, email, entrymsg, mlock, keeptopic, peace, "
            "restricted, secureops, signkick, topiclock, modes, protected)" % TABLE
        )
        db.commit()
        _db = db


def __del__(ctx):
    global _db
    if _db is not None:
        _db.close()
        _db = None
