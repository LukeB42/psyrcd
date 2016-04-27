# ChanServ.py for Psyrcd.
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

log             = cache['config']['logging']
TABLE           = "chanserv"
DB_FILE         = "./services.db"
MAX_OPS         = False
CS_IDENT        = "ChanServ!services@" + cache['config']['SRV_DOMAIN']
NS_TABLE        = "nickserv"
MAX_RECORDS     = 5000
MAX_CHANNELS    = 25
MAX_DAYS_UNUSED = 62


class Channel(object):
    """
    A dictionary-like object for channel records.
    """
    def __init__(self, channel):
        self.channel = channel
        self.db = cache['db']
        self.c = self.db.cursor()
        self.c.execute("SELECT * FROM %s WHERE channel=?" % \
            TABLE, (self.channel,))
        self.r = self.c.fetchone()
        if not self.r:
            self.channel = ''

    def __getitem__(self, key):
        self.c.execute("SELECT * FROM %s WHERE channel=?" % \
            TABLE, (self.channel,))
        self.r = self.c.fetchone()
        if self.r and key in self.r.keys():
             if key in ['operators', 'modes', 'bans', 'protected']:
                if ':' in self.r[key]:
                    return(dict([x.split(':') for x in self.r[key].split(',')]))
                else: return dict()
             else: return(self.r[key])
        else: raise CSError("Invalid key")

    def __setitem__(self, key, value):
        if self.r:
            if ':' in key:
                k,v = key.split(':')
                o = self[k]
                if type(o) == dict:
                    if MAX_OPS and (k == 'operators'):
                        if v not in o and len(o) >= MAX_OPS: return()
                    o[v]=value
                    v=str(o)\
                        .replace('{','')\
                        .replace('}','')\
                        .replace("u'",'')\
                        .replace(' ','')\
                        .replace("'",'')
                    self.c.execute("UPDATE %s SET %s=? WHERE channel=?" % \
                        (TABLE, k), (v, self.channel))
                    self.db.commit()
            elif key in self.r.keys():
                self.c.execute("UPDATE %s SET %s=? WHERE channel=?" % \
                    (TABLE,key), (value, self.channel))
                self.db.commit()
            else: raise CSError("Invalid key")
        else: raise CSError("Invalid channel")

    def __delitem__(self, key):
        if ':' in key:
            k,v = key.split(':')
            o = self[k]
            if type(o) == dict:
                if v in o:
                    del o[v]
                    v=str(o)\
                        .replace('{','')\
                        .replace('}','')\
                        .replace("u'",'')\
                        .replace(' ','')\
                        .replace("'",'')
                    self.c.execute("UPDATE %s SET %s=? WHERE channel=?" % \
                        (TABLE,k), (v,self.channel))
                    self.db.commit()
        elif key == 'channel': self.c.execute("DELETE FROM %s WHERE channel=?" % TABLE, (self.channel,))
        else: self[key] = ''

    def keys(self):
        if self.r: return(self.r.keys())
        else: return([])

    def __repr__(self):
        if self.r: return("<Channel object for %s at %s>" % \
            (self.channel,hex(id(self))))
        else: return("<Channel object at %s>" % hex(id(self)))

def re_to_irc(r, displaying=True):
    if not displaying:
        r = re.sub('\.','\\\.',r)
        r = re.sub('\*','.*',r)
    else:
        r = re.sub('\\\.','.',r)
        r = re.sub('\.\*','*',r)
    return(r)

def op_cmp(user,target):
    if user != 'q' and target == 'q': return false
    elif (user != 'a' and user != 'q') and (target == 'a' or target == 'q'):
        return False
    elif (user != 'o' and user != 'a' and user != 'q') \
    and (target == 'o' or target == 'a' or target == 'q'):
        return False
    else:
        return True

def is_op(nick, channel):
    if 'h' in channel.modes and nick in channel.modes['h']:
        return(True)
    elif 'o' in channel.modes and nick in channel.modes['o']:
        return(True)
    elif 'a' in channel.modes and nick in channel.modes['a']:
        return(True)
    elif 'q' in channel.modes and nick in channel.modes['q']:
        return(True)
    else:
        return(False)

def secureops(channel):
    for user in channel.clients:
        if not 'R' in user.modes or (user.nick not in ops and user.nick != c['owner']):
            if 'q' in channel.modes and user.nick in channel.modes['q']: csmode(channel,'-q',user.nick)
            if 'a' in channel.modes and user.nick in channel.modes['a']: csmode(channel,'-a',user.nick)
            if 'o' in channel.modes and user.nick in channel.modes['o']: csmode(channel,'-o',user.nick)
            if 'h' in channel.modes and user.nick in channel.modes['h']: csmode(channel,'-h',user.nick)
            if 'v' in channel.modes and user.nick in channel.modes['v']: csmode(channel,'-v',user.nick)
    csmsg("Enforced SecureOps.")

def restrict(channel):
    for user in channel.clients.copy():
        if not 'R' in user.modes or (user.nick not in ops and user.nick != c['owner']):
            for op_list in channel.ops:
                if user.nick in op_list: op_list.remove(user.nick)
            client.broadcast(channel.name, ':%s KICK %s %s :RESTRICTED' % \
                (CS_IDENT, channel.name, user.nick))
            user.channels.pop(channel.name)
            channel.clients.remove(user)
    csmsg("Enforced RESTRICTED.")

def init_channel(client, channel):
    """
    Handle a channel being initialised, or a client joining a registered one.
    """
    c = Channel(channel.name)
    if c.r:
        ops = c['operators']
        protected = c['protected']

        # Succession/Expiration
        db = cache['db']
        cur = db.cursor()
        cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (c['owner'],))
        r = cur.fetchone()
        if not r:
            if c['successor']:
                cur.execute("SELECT * FROM %s WHERE nick=?" % \
                    NS_TABLE, (c['successor'],))
                s = cur.fetchone()
                if s:
                    c['owner'] = c['successor']
                    c['successor'] = ''
                    del s
                else:
                    del c['channel']
                    return(None)
            else:
                del c['channel']
                return(None)
        elif not 'R' in channel.modes: csmode(channel,'+R')

        # Bans
        if not client.oper and (client.nick != c['owner'] or \
            ('R' not in client.modes and client.nick == c['owner'])) and \
            (client.nick not in protected or ('R' not in client.modes and client.nick in protected)):
            bans = c['bans']
            for b in bans.keys():
                if re.match(b, client.client_ident(True)):
                    return(':%s NOTICE %s :Cannot join %s. (Banned)' % (CS_IDENT,client.nick,channel.name))

        # Restricted
        if not client.oper and c['restricted']:
            if not 'R' in client.modes or (client.nick != c['owner'] \
                and client.nick not in ops and client.nick not in protected):
                return(':%s NOTICE %s :Cannot join %s. (Restricted)' % (CS_IDENT,client.nick,channel.name))

        # Topic/KeepTopic
        if c['topic'] and c['keeptopic'] and not len(channel.clients) \
            and channel.topic != c['topic']:
            channel.topic = c['topic']
            channel.topic_by = c['topic_by']
            channel.topic_time = c['topic_time']

        # Entrymsg
        if c['entrymsg']: csmsg("[%s] %s" % (channel.name, c['entrymsg']))

        # MLock
        if c['mlock']:
            for mode, settings in c['modes'].items():
                if ',' in settings: settings = settings.split(',')
                csmode(channel,mode,settings)

        # Operators
        if 'o' in channel.supported_modes and client.nick in channel.modes['o']:
            channel.modes['o'].remove(client.nick)
        if 'R' in client.modes and (client.nick == c['owner'] or client.nick == c['successor']): 
            c['time_use'] = time.time()
            csmode(channel,'+q',client.nick)
        if 'R' in client.modes and client.nick in ops  and(client.nick != c['owner'] \
            and client.nick != c['successor']):
            c['time_use'] = time.time()
            csmode(channel,'+'+ops[client.nick],client.nick)
        del db,cur,r
    elif 'R' in channel.modes: csmode(channel, '-R')
    del c
    return(None)

def escape(query): return query.replace("'","")

def csmsg(msg):
    client.broadcast(client.nick, ":%s NOTICE %s :%s" % \
        (CS_IDENT,client.nick,msg))

def csmode(channel, mode, args=None):
    if type(mode) == str or type(mode) == unicode: mode=[mode]
    for x in mode:
        f = x[0]
        m = x[1:]
        if type(channel) == str:
            channel = client.server.channels.get(channel)
        if channel and m in channel.supported_modes:
            if f == '+' and not m in channel.modes: channel.modes[m]=[]
            if f == '+' and not args in channel.modes[m]:
                if type(args) == list: channel.modes[m].extend(args)
                elif args: channel.modes[m].append(args)
            elif f == '-':
                if args and args in channel.modes[m]: channel.modes[m].remove(args)
                else: del channel.modes[m]
            if not args: client.broadcast(channel.name, ':%s MODE %s %s' % (CS_IDENT,channel.name,f+m))
            else: client.broadcast(channel.name, ':%s MODE %s %s %s' % (CS_IDENT,channel.name,f+m,args))

def fmt_timestamp(ts): return datetime.datetime.fromtimestamp(int(ts)).strftime('%b %d %H:%M:%S %Y')

def csmsg_list(t):
    for r in t:
        if client.oper: ip = " Owner: %s," % r['owner']
        else: ip = ''
        chan = client.server.channels.get(r['channel'])
        if chan:
            if 'R' in chan.modes: csmsg("\x02\x033%s\x0F:%s Description: %s, Registered: %s" % \
                (r['channel'], ip, r['description'], fmt_timestamp(r['time_reg'])))
            else: csmsg("\x02\x032%s\x0F:%s Description: %s, Registered: %s" % \
                (r['channel'], ip, r['description'], fmt_timestamp(r['time_reg'])))
        else: csmsg("\x02%s\x0F:%s Description: %s, Registered: %s" % \
            (r['channel'], ip, r['description'], fmt_timestamp(r['time_reg'])))
    csmsg("End of \x02LIST\x0F command.")

def is_expired(seconds):
    t = time.time()
    seconds = t - seconds
    minutes, seconds = divmod(seconds, 60)
    hours,   minutes = divmod(minutes, 60)
    days,    hours   = divmod(hours, 24)
    weeks,   days    = divmod(days, 7)
    if MAX_DAYS_UNUSED >= days+(weeks*7):
        return False
    else:
        return True

class CSError(Exception):
    def __init__(self, value): self.value = value # causes error messages to be
    def __str__(self): return(repr(self.value))   # dispersed to umode:W users

if 'init' in dir():
    provides=['command:chanserv,cs:Channel registration service.', 'cmode:R:Registered channel.']
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
            db.execute("CREATE TABLE IF NOT EXISTS %s (channel, password, description, \
                owner, operators, bans, topic, topic_by, topic_time, time_reg REAL, time_use REAL, \
                successor, url, email, entrymsg, mlock, keeptopic, peace, restricted, secureops, signkick, \
                topiclock, modes, protected)" % TABLE)
            db.commit()
    else:
        if 'db' in cache:
            cache['db'].close()
            del cache['db']

if 'new' in dir() and 'channel' in dir():
    cancel = init_channel(client,channel)
    if not cancel: del cancel

# The following happens when the server detects
# that a channel carrying our mode is doing something.
# Here we can determine what the client is doing, and then
# modify the client, the server, and/or command parameters.
if 'func' in dir():
    c = Channel(channel.name)
    if c.r:

        if func.__name__ == 'handle_join':
            cancel = init_channel(client,channel)
            if not cancel: del cancel

        elif func.__name__ == 'handle_topic':
            if client.oper or is_op(client.nick, channel):
                if c['topiclock']:
                    cancel = ':%s NOTICE %s :Topic locked for %s.' % \
                        (CS_IDENT,client.nick,channel.name)
                elif ':' in params and is_op(client.nick, channel):
                    c['topic'] = params.split(':')[1]
                    c['topic_by'] = client.nick
                    c['topic_time'] = str(time.time())[:10]

        elif func.__name__ == 'handle_kick':
            if params.split()[1] == c['owner']:
                params = params.split()
                user = client.server.clients.get(params[1])
                if user and 'R' in user.modes and user in channel.clients:
                    params[1:] = '_'
                    csmsg("Cannot kick channel Founder.")
                params = ' '.join(params)
            elif c['peace']:
                if not client.oper and (client.nick != c['owner'] or 'R' not in client.modes):
                    cancel = ':%s NOTICE %s :Cannot use KICK in \x02%s\x0F. (Peace)' % \
                        (CS_IDENT,client.nick,channel.name)
            elif params.split()[1] in c['protected']:
                user = client.server.clients.get(params.split()[1])
                if user and 'R' in user.modes:
                    cancel = ':%s NOTICE %s :Cannot kicked protected user \x02%s\x0F from \x02%s\x0F.' % \
                        (CS_IDENT,client.nick,user.nick,channel.name)

        elif func.__name__ == 'handle_mode':
            # Mode Lock
            if c['mlock'] and not client.oper and (client.nick != c['owner'] \
            or (client.nick == c['owner'] and 'R' not in client.modes)):
                cancel = ':%s NOTICE %s :Modes are locked for \x02%s\x0F.' % \
                    (CS_IDENT,client.nick,channel.name)

            # SecureOps / Peace
            elif not client.oper and (c['secureops'] or c['peace'] or c['protected']) \
                and is_op(client.nick, channel):
                target=''
                mode = params.split(' ',1)[1]
                if ' ' in mode: mode,target = mode.split(' ',1)
                if mode[1:] in ['v','h','o','a','q']:
                    target = client.server.clients.get(target)
                    ops = c['operators']
                    if c['secureops']:
                        if target and target.nick not in ops:
                            cancel = ':%s NOTICE %s :\x02%s\x0F is not in any of the access lists for \x02%s\x0F. (SecureOps)' % \
                                (CS_IDENT,client.nick,target.nick,channel.name)
                        elif target and not 'R' in target.modes:
                            cancel = ':%s NOTICE %s :\x02%s\x0F is not identified with services. (SecureOps)' % \
                                (CS_IDENT,client.nick,target.nick)
                    elif (c['peace'] and mode[0] == '-') and ('R' not in client.modes or client.nick != c['owner']):
                            cancel = ':%s NOTICE %s :Cannot revoke privileges on \x02%s\x0F. (Peace)' % \
                                (CS_IDENT,client.nick,channel.name)
                    elif mode[0] == '-' and target and target.nick in c['protected'] and 'R' in target.modes:
                        cancel = ':%s NOTICE %s :Cannot revoke privileges on \x02%s\x0F from protected user \x02%s\x0F.' % \
                            (CS_IDENT,client.nick,channel.name,target.nick)

    elif 'R' in channel.modes: csmode(channel.name,'-R')
    del c

# This namespace indicates a client is retrieving
# the list of modes in a channel where one of our
# cmodes is in use.
if 'display' in dir() and 'channel' in dir():
    output = '(Registered.)'

if 'command' in dir():
    client.last_activity = str(time.time())[:10]
    params = escape(params)
    cmd=params
    args=''
    if ' ' in params:
        cmd,args = params.split(' ',1)
        cmd,args=(cmd.lower(),args.lower())
    if cmd == 'help' or not cmd:
        if not args:
            csmsg("\x02/CHANSERV\x0F allows you to register and control various aspects of")
            csmsg("channels. ChanServ can often prevent malicious users from \"taking")
            csmsg("over\" channels by limiting who is allowed channel operator")
            csmsg("privileges. Available commands are listed below; to use them, type")
            csmsg("\x02/CHANSERV \x1Fcommand\x0F. For more information on a specific command,")
            csmsg("type \x02/CHANSERV HELP \x1Fcommand\x0F.")
            csmsg("")
            csmsg("     REGISTER    Register a channel")
            csmsg("     SET         Set channel options and information")
            csmsg("     SOP         Modify the list of SOP users")
            csmsg("     AOP         Modify the list of AOP users")
            csmsg("     HOP         Maintains the HOP (HalfOP) list for a channel")
            csmsg("     VOP         Maintains the VOP (VOiced People) list for a channel")
            csmsg("     DROP        Cancel the registration of a channel")
            csmsg("     BAN         Bans a selected host on a channel")
            csmsg("     UNBAN       Remove ban on a selected host from a channel")
            csmsg("     CLEAR       Tells ChanServ to clear certain settings on a channel")
            csmsg("     OWNER       Gives you owner status on channel")
            csmsg("     DEOWNER     Removes your owner status on a channel")
            csmsg("     PROTECT     Protects a selected nick on a channel")
            csmsg("     DEPROTECT   Deprotects a selected nick on a channel")
            csmsg("     OP          Gives Op status to a selected nick on a channel")
            csmsg("     DEOP        Deops a selected nick on a channel")
            csmsg("     HALFOP      Halfops a selected nick on a channel")
            csmsg("     DEHALFOP    Dehalfops a selected nick on a channel")
            csmsg("     VOICE       Voices a selected nick on a channel")
            csmsg("     DEVOICE     Devoices a selected nick on a channel")
            csmsg("     INVITE      Tells ChanServ to invite you into a channel")
            csmsg("     KICK        Kicks a selected nick from a channel")
            csmsg("     LIST        Lists all registered channels matching a given pattern")
            csmsg("     LOGOUT      This command will logout the selected nickname")
            csmsg("     TOPIC       Manipulate the topic of the specified channel")
            csmsg("     INFO        Lists information about the named registered channel")
            csmsg("     APPENDTOPIC Add text to a channels topic")
            csmsg("     ENFORCE     Enforce various channel modes and set options")
            csmsg("")
            csmsg("Note that any channel which is not used for %i days" % MAX_DAYS_UNUSED)
            csmsg("(i.e. which no user on the channel's access list enters")
            csmsg("for that period of time) will be automatically dropped.")

        elif args == 'register':
            csmsg("Syntax: \x02REGISTER \x1Fchannel\x0F \x02\x1Fpassword\x0F \x02\x1Fdescription\x0F")
            csmsg("")
            csmsg("Registers a channel in the ChanServ database.  In order")
            csmsg("to use this command, you must first be a channel operator")
            csmsg("on the channel you're trying to register.  The password")
            csmsg("is used with the \x02IDENTIFY\x0F command to allow others to")
            csmsg("make changes to the channel settings at a later time.")
            csmsg("The last parameter, which \x02must\x0F be included, is a")
            csmsg("general description of the channel's purpose.")
            csmsg("")
            csmsg("When you register a channel, you are recorded as the")
            csmsg("\"founder\" of the channel.  The channel founder is allowed")
            csmsg("to change all of the channel settings for the channel;")
            csmsg("ChanServ will also automatically give the founder")
            csmsg("channel-operator privileges when s/he enters the channel.")
            csmsg("See the \x02ACCESS\x0F command (\x02/ChanServ HELP ACCESS\x0F) for")
            csmsg("information on giving a subset of these privileges to")
            csmsg("other channel users.")
            csmsg("")
            csmsg("NOTICE: In order to register a channel, you must have")
            csmsg("first registered your nickname.  If you haven't,")
            csmsg("use \x02/NickServ HELP\x0F for information on how to do so.")
            csmsg("")
            csmsg("Note that any channel which is not used for %i days" % MAX_DAYS_UNUSED)
            csmsg("(i.e. which no user on the channel's access list enters")
            csmsg("for that period of time) will be automatically dropped.")

        elif args == 'set':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02\x1Foption\x0F \x02\x1Fparameters\x0F")
            csmsg("")
            csmsg("Allows the channel founder to set various channel options")
            csmsg("and other information.")
            csmsg("")
            csmsg("Available options:")
            csmsg("")
            csmsg("     FOUNDER       Set the founder of a channel")
            csmsg("     SUCCESSOR     Set the successor for a channel")
            csmsg("     PASSWORD      Set the founder password")
            csmsg("     DESC          Set the channel description")
            csmsg("     URL           Associate a URL with the channel")
            csmsg("     EMAIL         Associate an E-mail address with the channel")
            csmsg("     ENTRYMSG      Set a message to be sent to users when they")
            csmsg("                   enter the channel")
            csmsg("     MLOCK         Lock channel modes on or off")
            csmsg("     KEEPTOPIC     Retain topic when channel is not in use")
            csmsg("     PEACE         Regulate the use of critical commands")
            csmsg("     RESTRICTED    Restrict access to the channel")
            csmsg("     SECUREOPS     Stricter control of chanop status")
            csmsg("     SIGNKICK      Sign kicks that are done with KICK command")
            csmsg("     TOPICLOCK     Topic can only be changed with TOPIC")
            csmsg("")
            csmsg("Type \x02/CHANSERV HELP SET \x1Foption\x0F for more information on a")
            csmsg("particular option.")

        if args == 'set founder':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02FOUNDER \x1Fnick\x0F")
            csmsg("")
            csmsg("Changes the founder of a channel. The new nickname must")
            csmsg("be a registered one.")

        elif args == 'set successor':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02SUCCESSOR \x1Fnick\x0F")
            csmsg("")
            csmsg("Changes the successor of a channel. If the founders'")
            csmsg("nickname nickname expires or is dropped while the channel is still")
            csmsg("registered, the successor will become the new founder of the")
            csmsg("channel. However, if the successor already has too many")
            csmsg("channels registered (%i), the channel will be dropped" % MAX_CHANNELS)
            csmsg("instead, just as if no successor had been set. The new")
            csmsg("nickname must be a registered one.")

        elif args == 'set password':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02PASSWORD \x1Fpassword\x0F")
            csmsg("")
            csmsg("Sets the password used to drop the channel.")

        elif args == 'set desc':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02DESC \x1Fdescription\x0F")
            csmsg("")
            csmsg("Sets the description of the channel, which shows up with")
            csmsg("The \x02LIST\x0F and \x02INFO\x0F commands.")

        elif args == 'set url':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02URL \x1Furl\x0F")
            csmsg("")
            csmsg("Associates the given URL with the channel. This URL will")
            csmsg("be displayed whenever someone requests information on the")
            csmsg("channel with the \x02INFO\x0F command.")

        elif args == 'set email':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02EMAIL \x1Femail\x0F")
            csmsg("")
            csmsg("Associates the given E-Mail address with the channel.")
            csmsg("This address will be displayed whenever an IRC Operator")
            csmsg("requests information on the channel with the \x02INFO\x0F")
            csmsg("command. This can help IRC Operators issue new passwords.")

        elif args == 'set entrymsg':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02ENTRYMSG \x1Fmessage\x0F")
            csmsg("")
            csmsg("Sets the message which will be sent via /notice to users")
            csmsg("when they enter the channel. If \x02message\x0F is \"\x02off\x0F\" then no")
            csmsg("message will be shown.")

        elif args == 'set mlock':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02MLOCK {ON|OFF}\x0F")
            csmsg("")
            csmsg("Sets the mode-lock parameter for the channel. ChanServ")
            csmsg("allows you to lock active channel modes to a channel,")
            csmsg("even across channel instances. Modes involving sophisticated")
            csmsg("parameters (non-list, string, integer or floating point")
            csmsg("values) cannot be locked.")

        elif args == 'set keeptopic':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02KEEPTOPIC {ON|OFF}\x0F")
            csmsg("")
            csmsg("Enables or disables \x02topic retention\x0F for a channel.")
            csmsg("When \x02topic retention\x0F is set, the topic for the channel")
            csmsg("will be remembered by ChanServ even after the last user")
            csmsg("leaves the channel, and will be restored the next time")
            csmsg("the channel is created.")

        elif args == 'set peace':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02PEACE {ON|OFF}\x0F")
            csmsg("")
            csmsg("When \x02peace\x0F is set, a user won't be able to kick, ban")
            csmsg("or remove channel status from another user.")

        elif args == 'set restricted':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02RESTRICTED {ON|OFF}\x0F")
            csmsg("")
            csmsg("Enables or disables the \x02restricted access\x0F option for a")
            csmsg("channel. When \x02restricted access\x0F is set, users not on")
            csmsg("the access list will instead be denied entry to the channel.")

        elif args == 'set secureops':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02SECUREOPS {ON|OFF}\x0F")
            csmsg("")
            csmsg("When \x02secure ops\x0F is set, users who are not on the userlist")
            csmsg("will not be allowed chanop status.")

        elif args == 'set signkick':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02SIGNKICK {ON|OFF}\x0F")
            csmsg("")
            csmsg("Enables or disables signed kicks for a channel.")
            csmsg("When \x02SIGNKICK\x0F is set, kicks issued with the")
            csmsg("ChanServ \x02KICK\x0F command will have the nick that used the")
            csmsg("command in their reason.")

        elif args == 'set topiclock':
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02TOPICLOCK {ON|OFF}\x0F")
            csmsg("")
            csmsg("Enables or disables the \x02topic lock\x0F for a channel.")
            csmsg("When \x02topic lock\x0F is set, ChanServ will not allow the")
            csmsg("channel topic to be changed except by the \x02TOPIC\x0F")
            csmsg("command.")

        elif args == 'drop':
            csmsg("Syntax \x02DROP \x1Fchannel\x0F \x02\x1Fpassword\x0F")
            csmsg("")
            csmsg("Unregisters the named channel ")
            if client.oper:
                csmsg("IRC Operators may supply anything as a password.")

        elif args == 'enforce':
            csmsg("Syntax: \x02ENFORCE \x1Fchannel\x0F \x02\x1Fwhat\x0F")
            csmsg("")
            csmsg("Enforce various channel modes and options. The \x1Fchannel\x0F")
            csmsg("option indicates what channel to enforce the modes and options")
            csmsg("on. The \x1Fwhat\x0F option indicates what modes and options to")
            csmsg("enforce, and can be any of SET, SECUREOPS, RESTRICTED or MODES.")
            csmsg("")
            csmsg("If \x1Fwhat\x0F is SET, it will enforce SECUREOPS and RESTRICTED")
            csmsg("on the users currently in the channel, if they are set. Give")
            csmsg("SECUEROPS to enforce the SECUREOPS option, even if it is not")
            csmsg("enabled. Use RESTRICTED to enforce the RESTRICTED option, also")
            csmsg("if it is not enabled.")
            csmsg("")
            csmsg("If \x1Fwhat\x0F is MODES, it will enforce any stored modes")
            csmsg("associated with the channel.")
            csmsg("")
            csmsg("Limited to channel Founders and IRC Operators.")

        elif args == 'ban':
            csmsg("Syntax: \x02BAN \x1Fchannel\x0F \x02\x1Fmask\x0F")
            csmsg("")
            csmsg("Bans a selected mask on a channel. Limited to AOPs")
            csmsg("and above, channel owners and IRC Operators.")

        elif args == 'unban':
            csmsg("Syntax: \x02UNBAN \x1Fchannel\x0F \x02\x1Fmask\x0F")
            csmsg("")
            csmsg("Unbans a selected mask from a channel. Limited to AOPs")
            csmsg("and above, channel owners and IRC Operators.")

        elif args == 'sop':
            csmsg("Syntax: \x02SOP \x1Fchannel\x0F \x02ADD \x1Fnick\x0F")
            csmsg("        \x02SOP \x1Fchannel\x0F \x02DEL \x1Fnick\x0F")
            csmsg("        \x02SOP \x1Fchannel\x0F \x02LIST\x0F")
            csmsg("        \x02SOP \x1Fchannel\x0F \x02CLEAR\x0F")
            csmsg("")
            csmsg("Maintains the \x02SOP\x0F (SUperOp) \x02list\x0F for a channel.")
            csmsg("")
            csmsg("The \x02SOP ADD\x0F command adds the given nickname to the")
            csmsg("SOP list.")
            csmsg("")
            csmsg("The \x02SOP DEL\x0F command removes the given nick from the")
            csmsg("SOP list. If a list of entry numbers is given, those")
            csmsg("entries are deleted. (See the example for LIST below.)")
            csmsg("")
            csmsg("The \x02SOP LIST\x0F command displays the SOP list.")
            csmsg("")
            csmsg("The \x02SOP CLEAR\x0F command clears all entries of the")
            csmsg("SOP list.")
            csmsg("")
            csmsg("The \x02SOP ADD\x0F, \x02SOP DEL\x0F, \x02SOP LIST\x0F and \x02SOP CLEAR\x0F commands are")
            csmsg("limited to the channel founder.")

        elif args == 'aop':
            csmsg("Syntax: \x02AOP \x1Fchannel\x0F \x02ADD \x1Fnick\x0F")
            csmsg("        \x02AOP \x1Fchannel\x0F \x02DEL \x1Fnick\x0F")
            csmsg("        \x02AOP \x1Fchannel\x0F \x02LIST\x0F")
            csmsg("        \x02AOP \x1Fchannel\x0F \x02CLEAR\x0F")
            csmsg("")
            csmsg("Maintains the \x02AOP\x0F (AutoOp) \x02list\x0F for a channel. The AOP")
            csmsg("list gives users the right to be auto-opped on you channel,")
            csmsg("to unban or invite themselves if needed, to have their")
            csmsg("greet message showed on join, and so on.")
            csmsg("")
            csmsg("The \x02AOP ADD\x0F command adds the given nicknamet o the")
            csmsg("AOP list.")
            csmsg("")
            csmsg("The \x02AOP DEL\x0F commmand removes the given nick from the")
            csmsg("AOP list. If  list of entry numbers is given, those")
            csmsg("entries are deleted. (See the example for LIST below.)")
            csmsg("")
            csmsg("The \x02AOP LIST\x0F command displays the AOP list.")
            csmsg("")
            csmsg("The \x02AOP CLEAR\x0F command clears all entries of the")
            csmsg("AOP list.")
            csmsg("")
            csmsg("The \x02AOP ADD\x0F and \x02AOP DEL\x0F commands are limited to")
            csmsg("SOP or above, while the \x02AOP CLEAR\x0F command can only")
            csmsg("be used bu the channel founder. However, any use on the")
            csmsg("AOP list may use the \x02AOP LIST\x0F command.")

        elif args == 'hop':
            csmsg("Syntax: \x02HOP \x1Fchannel\x0F \x02ADD \x1Fnick\x0F")
            csmsg("        \x02HOP \x1Fchannel\x0F \x02DEL \x1Fnick\x0F")
            csmsg("        \x02HOP \x1Fchannel\x0F \x02LIST\x0F")
            csmsg("        \x02HOP \x1Fchannel\x0F \x02CLEAR\x0F")
            csmsg("")
            csmsg("Maintains the \x02HOP\x0F (HalfOp) \x02list\x0F for a channel. The HOP")
            csmsg("list gives users the right to be auto-halfopped on your")
            csmsg("channel.")
            csmsg("")
            csmsg("The \x02HOP ADD\x0F command adds the given nickname to the")
            csmsg("HOP list.")
            csmsg("")
            csmsg("The \x02HOP DEL\x0F command removes the given nick from the")
            csmsg("HOP list.")
            csmsg("")
            csmsg("The \x02HOP LIST\x0F command displays te HOP list.")
            csmsg("")
            csmsg("The \x02HOP CLEAR\x0F command clears all entries of the")
            csmsg("HOP list.")

        elif args == 'vop':
            csmsg("Syntax: \x02VOP \x1Fchannel\x0F \x02ADD \x1Fnick\x0F")
            csmsg("        \x02VOP \x1Fchannel\x0F \x02DEL \x1Fnick\x0F")
            csmsg("        \x02VOP \x1Fchannel\x0F \x02LIST\x0F")
            csmsg("        \x02VOP \x1Fchannel\x0F \x02CLEAR\x0F")
            csmsg("")
            csmsg("Maintains the \x02VOP\x0F (VOiced People) \x02list\x0F for a channel.")
            csmsg("The VOP list allows users to be auto-voices and to voice")
            csmsg("themselves if they aren't.")
            csmsg("")
            csmsg("The \x02VOP ADD\x0F command adds the given nickname to the")
            csmsg("VOP list.")
            csmsg("")
            csmsg("The \x02VOP DEL\x0F command removes the given nick from the")
            csmsg("VOP list.")
            csmsg("")
            csmsg("The \x02VOP LIST\x0F command displays the VOP list.")
            csmsg("")
            csmsg("The \x02VOP CLEAR\x0F command clears all entries of the")
            csmsg("VOP list.")

        elif args == 'owner':
            csmsg("Syntax: \x02OWNER \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg("")
            csmsg("Gives owner status to a selected nick on \x02channel\x0F.")
            csmsg("Limited to those with founder access on the channel.")

        elif args == 'deowner':
            csmsg("Syntax: \x02DEOWNER \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg("")
            csmsg("Removes owner status from a selected nick on \x02channel\x0F.")
            csmsg("Limited to those with founder access on the channel.")

        elif args == 'op':
            csmsg("Syntax: \x02OP \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg("")
            csmsg("Ops a selected nick on a channel.")
            csmsg("Limited to AOPs and above.")

        elif args == 'deop':
            csmsg("Syntax: \x02DEOP \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg("")
            csmsg("Deops a selected nick on a channel.")
            csmsg("Limited to AOPs and above.")


        elif args == 'halfop':
            csmsg("Syntax: \x02HALFOP \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg("")
            csmsg("Halfops a selected nick on a channel.")
            csmsg("Limited to AOPs and above.")

        elif args == 'dehalfop':
            csmsg("Syntax: \x02DEHALFOP \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg("")
            csmsg("Dehalfops a selected nick on a channel.")
            csmsg("Limited to AOPs and above.")

        elif args == 'voice':
            csmsg("Syntax: \x02VOICE \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg("")
            csmsg("Voices a selected nick on a channel.")
            csmsg("Limited to AOPs and above.")

        elif args == 'devoice':
            csmsg("Syntax: \x02DEVOICE \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg("")
            csmsg("Devoices a selected nick on a channel.")
            csmsg("Limited to AOPs and above.")

        elif args == 'kick':
            csmsg("Syntax \x02KICK \x1Fchannel\x0F \x02\x1Fnick\x0F \x02\x1Freason\x0F")
            csmsg("")
            csmsg("Kicks a selected nick on a channel, provided you have")
            csmsg("the rights to.")

        elif args == 'clear':
            csmsg("Syntax: \x02CLEAR \x1Fchannel\x0F \x02\x1Fwhat\x0F")
            csmsg("")
            csmsg("Tells ChanServ to clear certain settings on a channel. \x1fwhat\x0F")
            csmsg("can be any of the following:")
            csmsg("")
            csmsg("     MODES    Resets all modes on the channel, leaving only +Rnt")
            csmsg("              intact.")
            csmsg("     BANS     Clears all bans on the channel.")
            csmsg("     EXCEPTS  Clears all excepts on the channel.")
            csmsg("     OPS      Removes channel-operator (mode +o) from all channel")
            csmsg("              Operators.")
            csmsg("     HOPS     Removes channel half-operator status (mode +h) from")
            csmsg("              all channel HalfOps.")
            csmsg("     VOICES   Removes \"voice\" status (mode +v) from anyone with")
            csmsg("              that mode set.")
            csmsg("     USERS    Removes (kicks) all users from the channel who are")
            csmsg("              neither (User-Mode) +Q or authenticated as the")
            csmsg("              channel Founder.")
            csmsg("")
            csmsg("Limited to IRC Operators and those with Founder access on the")
            csmsg("channel.")

        elif args == 'protect':
            csmsg("Syntax: \x02PROTECT \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg("")
            csmsg("Protects a registered nick on a channel. This prevents the")
            csmsg("selected mick from having their privileges revoked, from")
            csmsg("being kicked and from matching ChanServ bans when joining.")
            csmsg("")
            csmsg("By default, limited to the founder, SOPs and IRC Operators.")

        elif args == 'deprotect':
            csmsg("Syntax: \x02DEPROTECT \x1Fchannel\x0F \x02\x1Fnick\x0F")
            csmsg("")
            csmsg("Deprotects a selected nick on a channel.")
            csmsg("Use \x02/CHANSERV HELP PROTECT\x0F to see a description of")
            csmsg("what the \x02PROTECT\x0F command protects.")
            csmsg("")
            csmsg("By default, limited to the founder, SOPs and IRC Operators.")

        else:
            if args: csmsg("No help available for \x02%s\x0F." % args)

    elif cmd == 'register':
        if not args or len(args.split()) < 3:
            csmsg("Syntax: \x02/CHANSERV REGISTER \x1Fchannel\x0F \x02\x1Fpassword\x0F \x02\x1Fdescription\x0F")
        elif not 'R' in client.modes:
            csmsg("A registered nickname is required for channel registration.")
        else:
            channel_name, password, description = args.split(' ',2)
            password = hashlib.sha1(args.encode('utf-8')).hexdigest()
            if not re.match('^#([a-zA-Z0-9_])+$', channel_name):
                csmsg("\x02%s\x0F is not a valid channel name.")
            else:
                r = None
                db = cache['db']
                c = db.cursor()
                c.execute("SELECT * FROM %s WHERE channel=?" % TABLE, (channel_name,))
                r = c.fetchone()
                if r: csmsg("\x02%s\x0F is already registered." % channel_name)
                else:
                    c.execute("SELECT * FROM %s WHERE owner=?" % TABLE, (client.nick,))
                    r = c.fetchall()
                    if len(r) >= MAX_CHANNELS:
                        csmsg("You already have %i channels registered to this nick:" % MAX_CHANNELS)
                        for i in r: csmsg("\x02%s\x0F, %s" % (i['channel'],fmt_timestamp(i['time_reg'])))
                        del i
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
                            TABLE, (channel_name,password,description,client.nick,'','',topic,topic_by,topic_time,t,t,
                            '','','','','','','','','','','','',''))
                        db.commit()
                        csmsg("Registered \x02%s\x0F to \x02%s\x0F." % (channel_name,client.nick))
                        client.broadcast('umode:W',':%s NOTICE * :%s has registered the channel \x02%s\x0F.' % \
                            (CS_IDENT, client.nick, channel_name))
                        if channel:
                            client.broadcast(channel_name, ':%s MODE %s +R' % (CS_IDENT,channel_name))
                    del db,c,r

    elif cmd == 'set':
        if not args or len(args.split(' ',2)) < 3:
            csmsg("Syntax: \x02SET \x1Fchannel\x0F \x02\x1Foption\x0F \x02\x1Fparameters\x0F")
            csmsg("\x02/CHANSERV HELP SET\x0F for more information.")
        else:
            channel, option = (args.split()[0], args.split()[1])
            params = escape(params.split(' ',3)[3])
            c = Channel(channel)
            if not 'R' in client.modes:
                csmsg("Access denied.")
            elif not c.r:
                csmsg("\x02%s\x0F is not a registered channel." % channel)
            else:
                if not 'A' in client.modes and client.nick != c['owner'] and client.nick != c['successor']:
                    csmsg("Access denied.")
                else:
                    if option == 'founder':
                        if not 'A' in client.modes and client.nick != c['owner']:
                            csmsg("Access denied.")
                        else:
                            db = cache['db']
                            cur = db.cursor()
                            cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (params,))
                            r = cur.fetchone()
                            if not r: csmsg("\x02%s\x0F isn't a registered nick." % params)
                            else:
                                c['owner'] = escape(params)
                                csmsg("Founder for %s changed to \x02%s\x0F." % (channel,params))
                            del db,cur,r

                    elif option == 'successor':
                        if not 'A' in client.modes and client.nick != c['owner']:
                            csmsg("Access denied.")
                        else:
                            db = cache['db']
                            cur = db.cursor()
                            cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (params,))
                            r = cur.fetchone()
                            if not r: csmsg("\x02%s\x0F isn't a registered nick." % params)
                            else:
                                c['successor'] = escape(params)
                                csmsg("Successor for %s changed to \x02%s\x0F." % (channel,params))
                            del db,cur,r

                    elif option == 'password':
                        if not 'A' in client.modes and client.nick != c['owner']:
                            csmsg("Access denied.")
                        else:
                            c['password'] = hashlib.sha1(params.encode('utf-8')).hexdigest()
                            csmsg("Password for %s changed to \x02%s\x0F." % (channel,params))

                    elif option == 'desc':
                        c['description'] = escape(params)
                        csmsg("Description for %s changed to \x02%s\x0F." % (channel,params))

                    elif option == 'url':
                        c['url'] = escape(params)
                        csmsg("URL for %s changed to \x02%s\x0F" % (channel,params))

                    elif option == 'email':
                        if not 'A' in client.modes and client.nick != c['owner']:
                            csmsg("Access denied.")
                        else:
                            c['email'] = escape(params)
                            csmsg("Email address for %s changed to \x02%s\x0F." % (channel,params))

                    elif option == 'entrymsg':
                        if params.lower() == 'off':
                            c['entrymsg'] = ''
                            csmsg("Entry message disabled for %s." % channel)
                        else: 
                            c['entrymsg'] = escape(params)
                            csmsg("Entry message for %s changed to \x02%s\x0F." % (channel,params))

                    elif option.lower() in ['mlock','keeptopic','peace', 'restricted', 'secureops', 'topiclock']:
                        if params.lower() == 'off' and not c[option] or params.lower() == c[option]:
                            csmsg("%s is already \x02%s\x0F for %s." % (option.title(), params.upper(), channel))
                        else:
                            if params.lower() == 'off':
                                if option.lower() == 'mlock': del c['modes']
                                c[option] = ''
                            else:
                                if option.lower() == 'mlock':
                                    chan = client.server.channels.get(channel)
                                    if not chan:
                                        csmsg("\x02%s\x0F isn't active at the moment. No modes appended." % chan)
                                    else:
                                        for mode, settings in chan.modes.items():
                                            if mode in ['v','h','o','a','q','b','e','R']: continue
                                            if type(settings) == list:
                                                c['modes:+%s' % mode] = ','.join(settings)
                                            # Comment the following line if you would like to persist
                                            # invites across channel deaths.
                                            elif str(mode) == '+i': c['modes:+%s' % mode] = ''
                                            elif type(settings) in [str, unicode, int, float]:
                                                c['modes:+%s' % mode ] = str(settings)
                                    csmsg("The following modes are locked for \x02%s\x0F: %s." % \
                                        (channel,', '.join(c['modes'].keys())))
                                c[option] = 'on'
                            csmsg("%s for %s set to \x02%s\x0F." % (option.title(),channel,params.upper()))
                    else:
                        csmsg("Unkown option \x02%s\x0F." % option.upper())
                        csmsg("\x02/CHANSERV HELP SET\x0F for more information.")
            del c

    elif cmd == 'enforce':
        if not args or len(args.split()) != 2: csmsg("Syntax: \x02ENFORCE \x1Fchannel\x0F \x02\x1Fwhat\x0F")
        else:
            chan,what = args.split()
            what = what.lower()
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if (not 'R' in client.modes or client.nick != c['owner']) and not client.oper:
                csmsg("Access denied.")
            elif not c.r: csmsg("\x02%s\x0F is not registered." % chan)
            elif not channel: csmsg("\x02%s\x0F is not in use." % chan)
            else:
                ops = c['operators']
                if what == 'set':
                    if c['secureops']: secureops(channel)
                    else: csmsg("Didn't enforce SecureOps.")
                    if c['restricted']: restrict(channel)
                    else: csmsg("Didn't enforce RESTRICTED.")
                elif what == 'secureops': secureops(channel)
                elif what == 'restricted': restrict(channel)
                elif what == 'modes':
                    modes = c['modes']
                    for_removal = []
                    for mode in channel.modes:
                        if '+'+mode not in modes and mode not in ['R','n','t','b','e','v','h','o','a','q']:
                            for_removal.append('-'+mode)
                    for mode in for_removal: csmode(channel,mode)
                    for mode, settings in c['modes'].items():
                        if not mode[1:] in channel.modes:
                            if ',' in settings: settings = settings.split(',')
                            csmode(channel,mode,settings)
                    if modes: csmsg("Enforced \x02%s\x0F on \x02%s\x0F." % (', '.join(modes.keys()),channel.name))
                    else: csmsg("Enforced modes.")
                else: csmsg("Unkown option \x02%s\x0F." % what)

    elif cmd == 'sop':
        if not args or args.split()[1].lower() not in ['add','del','list','clear']:
            csmsg("Syntax: \x02SOP \x1Fchannel\x0F \x02{ADD|DEL|LIST|CLEAR} [\x1Fnick\x0F\x02]\x0F")
            csmsg("\x02/CHANSERV HELP SOP\x0F for more information.")
        else:
            chan, params = args.split(' ',1)
            params = params.split()
            c = Channel(chan)
            if not c.r: csmsg("%s isn't registered." % chan)
            elif ('R' not in client.modes or client.nick != c['owner']) and not client.oper: csmsg("Access denied.")
            else:
                if params[0].lower() in ['add','del']:
                    nick = params[1]
                    db = cache['db']
                    cur = db.cursor()
                    cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (nick,))
                    r = cur.fetchone()
                    if not r: csmsg("Channel SOP lists may only contain registered nicknames.")
                    elif params[0].lower() == 'add':
                        c['operators:%s' % nick] = 'a'
                        csmsg("\x02%s\x0F added to %s SOP list." % (nick,chan))
                    elif params[0].lower() == 'del':
                        ops = c['operators']
                        if nick not in ops or (nick in ops and ops[nick] != 'a'):
                            csmsg("\x02%s\x0F is not in the SOP list for %s." % (nick,chan))
                        else:
                            del c['operators:%s' % nick]
                            csmsg("Removed \x02%s\x0F from %s SOP list." % (nick,chan))
                    del db,cur,r
                elif params[0].lower() == 'list':
                    ops = c['operators']
                    lst = [i for i in ops.items() if i[1] == 'a']
                    for x in lst: csmsg("\x02%s\x0F" % x[0])
                    csmsg("End of %s SOP list." % chan)
                elif params[0].lower() == 'clear':
                    ops = c['operators']
                    lst = [i for i in ops.items() if i[1] == 'a']
                    for x in lst: del c['operators:%s' % x[0]]
                    csmsg("Cleared %s SOP list." % chan)

    elif cmd == 'aop':
        if not args or args.split()[1].lower() not in ['add','del','list','clear']:
            csmsg("Syntax: \x02AOP \x1Fchannel\x0F \x02{ADD|DEL|LIST|CLEAR} [\x1Fnick\x0F\x02]\x0F")
            csmsg("\x02/CHANSERV HELP AOP\x0F for more information.")
        else:
            chan, params = args.split(' ',1)
            params = params.split()
            c = Channel(chan)
            if c.r: ops = c['operators']
            if not c.r: csmsg("%s isn't registered." % chan)
            elif (('R' not in client.modes or client.nick != c['owner']) and not client.oper) \
                and (client.nick not in ops or (client.nick in ops and (ops[client.nick] != 'a' and ops[client.nick] != 'q'))):
                csmsg("Access denied.")
            else:
                if params[0].lower() in ['add','del']:
                    nick = params[1]
                    db = cache['db']
                    cur = db.cursor()
                    cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (nick,))
                    r = cur.fetchone()
                    if not r: csmsg("Channel AOP lists may only contain registered nicknames.")
                    elif params[0].lower() == 'add':
                        c['operators:%s' % nick] = 'o'
                        csmsg("\x02%s\x0F added to %s AOP list." % (nick,chan))
                    elif params[0].lower() == 'del':
                        ops = c['operators']
                        if nick not in ops or (nick in ops and ops[nick] != 'o'):
                            csmsg("\x02%s\x0F is not in the AOP list for %s." % (nick,chan))
                        else:
                            del c['operators:%s' % nick]
                            csmsg("Removed \x02%s\x0F from %s AOP list." % (nick,chan))
                    del db,cur,r
                elif params[0].lower() == 'list':
                    lst = [i for i in ops.items() if i[1] == 'o']
                    for x in lst: csmsg("\x02%s\x0F" % x[0])
                    csmsg("End of %s AOP list." % chan)
                elif params[0].lower() == 'clear':
                    ops = c['operators']
                    lst = [i for i in ops.items() if i[1] == 'o']
                    for x in lst: del c['operators:%s' % x[0]]
                    csmsg("Cleared %s AOP list." % chan)

    elif cmd == 'hop':
        if not args or args.split()[1].lower() not in ['add','del','list','clear']:
            csmsg("Syntax: \x02HOP \x1Fchannel\x0F \x02{ADD|DEL|LIST|CLEAR} [\x1Fnick\x0F\x02]\x0F")
            csmsg("\x02/CHANSERV HELP HOP\x0F for more information.")
        else:
            chan, params = args.split(' ',1)
            params = params.split()
            c = Channel(chan)
            if c.r: ops = c['operators']
            if not c.r: csmsg("%s isn't registered." % chan)
            elif (('R' not in client.modes or client.nick != c['owner']) and not client.oper) \
                and (client.nick not in ops or (client.nick in ops \
                and (ops[client.nick] != 'o' and ops[client.nick] != 'a' and ops[client.nick] != 'q'))):
                csmsg("Access denied.")
            else:
                if params[0].lower() in ['add','del']:
                    nick = params[1]
                    db = cache['db']
                    cur = db.cursor()
                    cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (nick,))
                    r = cur.fetchone()
                    if not r: csmsg("Channel HOP lists may only contain registered nicknames.")
                    elif params[0].lower() == 'add':
                        c['operators:%s' % nick] = 'h'
                        csmsg("\x02%s\x0F added to %s HOP list." % (nick,chan))
                    elif params[0].lower() == 'del':
                        ops = c['operators']
                        if nick not in ops or (nick in ops and ops[nick] != 'h'):
                            csmsg("\x02%s\x0F is not in the HOP list for %s." % (nick,chan))
                        else:
                            del c['operators:%s' % nick]
                            csmsg("Removed \x02%s\x0F from %s HOP list." % (nick,chan))
                    del db,cur,r
                elif params[0].lower() == 'list':
                    lst = [i for i in ops.items() if i[1] == 'h']
                    for x in lst: csmsg("\x02%s\x0F" % x[0])
                    csmsg("End of %s HOP list." % chan)
                elif params[0].lower() == 'clear':
                    ops = c['operators']
                    lst = [i for i in ops.items() if i[1] == 'h']
                    for x in lst: del c['operators:%s' % x[0]]
                    csmsg("Cleared %s HOP list." % chan)

    elif cmd == 'vop':
        if not args or args.split()[1].lower() not in ['add','del','list','clear']:
            csmsg("Syntax: \x02VOP \x1Fchannel\ x0F\x02{ADD|DEL|LIST|CLEAR} [\x1Fnick\x0F\x02]\x0F")
            csmsg("\x02/CHANSERV HELP VOP\x0F for more information.")
        else:
            chan, params = args.split(' ',1)
            params = params.split()
            c = Channel(chan)
            if c.r: ops = c['operators']
            if not c.r: csmsg("%s isn't registered." % chan)
            elif (('R' not in client.modes or client.nick != c['owner']) and not client.oper) \
                and (client.nick not in ops or (client.nick in ops \
                and (ops[client.nick] != 'o' and ops[client.nick] != 'a' and ops[client.nick] != 'q'))):
                csmsg("Access denied")
            else:
                if params[0].lower() in ['add','del']:
                    nick = params[1]
                    db = cache['db']
                    cur = db.cursor()
                    cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (nick,))
                    r = cur.fetchone()
                    if not r: csmsg("Channel VOP lists may only contain registered nicknames.")
                    elif params[0].lower() == 'add':
                        c['operators:%s' % nick] = 'v'
                        csmsg("\x02%s\x0F added to %s VOP list." % (nick,chan))
                    elif params[0].lower() == 'del':
                        ops = c['operators']
                        if nick not in ops or (nick in ops and ops[nick] != 'v'):
                            csmsg("\x02%s\x0F is not in the VOP list for %s." % (nick,chan))
                        else:
                            del c['operators:%s' % nick]
                            csmsg("Removed \x02%s\x0F from %s VOP list." % (nick,chan))
                    del db,cur,r
                elif params[0].lower() == 'list':
                    lst = [i for i in ops.items() if i[1] == 'v']
                    for x in lst: csmsg("\x02%s\x0F" % x[0])
                    csmsg("End of %s VOP list." % chan)
                elif params[0].lower() == 'clear':
                    ops = c['operators']
                    lst = [i for i in ops.items() if i[1] == 'v']
                    for x in lst: del c['operators:%s' % x[0]]
                    csmsg("Cleared %s VOP list." % chan)

    elif cmd == 'ban':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax: \x02/CHANSERV BAN \x1F#channel\x0F \x02\x1Fmask\x0F")
        else:
            chan, mask = args.split(' ',1)
            chan = escape(chan)
            mask = escape(mask)
            if '!' not in mask and '@' not in mask: mask += '!*@*'
            c = Channel(chan)
            if not c.r: csmsg("\x02%s\x0F isn't registered." % chan)
            else:
                o = c['operators']
                if not client.oper and 'R' not in client.modes or client.nick != c['owner'] and client.nick not in o \
                    or (client.nick in o and (o[client.nick] == 'v' or  o[client.nick] == 'h')):
                    csmsg("Access denied.")
                else:
                    b = c['bans']
                    m = re_to_irc(mask,False)
                    if m in b: csmsg("\x02%s\x0F is already banned from %s." % (mask,chan))
                    else:
                        c['bans:%s' % m] = client.nick
                        csmsg("Banned \x02%s\x0F from %s." % (mask,chan))

    elif cmd == 'unban':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax: \x02/CHANSERV UNBAN \x1F#channel\x0F \x02\x1Fmask\x0F")
        else:
            chan, mask = args.split(' ',1)
            chan = escape(chan)
            mask = escape(mask)
            if '!' not in mask and '@' not in mask: mask += '!*@*'
            c = Channel(chan)
            if not c.r: csmsg("\x02%s\x0F isn't registered." % chan)
            else:
                o = c['operators']
                if not client.oper and 'R' not in client.modes or client.nick != c['owner'] and client.nick not in o \
                    or (client.nick in o and o[client.nick] == 'v' or client.nick in o and o[client.nick] == 'h'):
                    csmsg("Access denied.")
                else:
                    b = c['bans']
                    m = re_to_irc(mask,False)
                    if not m in b: csmsg("\x02%s\x0F isn't banned from %s." % (mask,chan))
                    else:
                        del c['bans:%s' % m]
                        csmsg("Unbanned \x02%s\x0F from %s." % (mask,chan))

    elif cmd == 'clear':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax: \x02CLEAR \x1Fchannel\x0F \x02\x1Fwhat\x0F")
        else:
            chan, what = args.split(' ',2)
            what = what.lower()
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not channel:
                csmsg("%s is not currently in use." % chan)
            elif (client.nick != c['owner'] or 'R' not in client.modes) and not client.oper:
                csmsg("Access denied.")
            else:
                if what == 'modes':
                    modes = channel.modes.copy()
                    [csmode(channel,'-'+mode) for mode in modes if mode not in ['n','t','R','e','b','v','h','o','a','q']]
                    csmsg("Modes reset for \x02%s\x0F." % chan)
                elif what == 'bans':
                    # Uncomment the following line if you would like this command
                    # to also clear ChanServ bans.
#                    del c['bans']
                    if 'b' in channel.modes:
                        channel.modes['b']=[]
                        csmsg("Bans cleared for \x02%s\x0F." % chan)
                elif what == 'excepts':
                    if 'e' in channel.modes:
                        channel.modes['e']=[]
                        csmsg("Excepts cleared for \x02%s\x0F." % chan)
                elif what == 'ops':
                    if 'o' in channel.modes and len(channel.modes['o']) > 0:
                        for nick in channel.modes['o']: csmode(channel,'-o',nick)
                        csmsg("Cleared Operators list on \x02%s\x0F" % chan)
                elif what == 'hops':
                    if 'h' in channel.modes and len(channel.modes['h']) > 0:
                        for nick in channel.modes['h']: csmode(channel,'-h',nick)
                        csmsg("Cleared Half-Operators list on \x02%s\x0F" % chan)
                elif what == 'voices':
                    if 'v' in channel.modes and len(channel.modes['v']) > 0:
                        for nick in channel.modes['v']: csmode(channel,'-v',nick)
                        csmsg("Cleared Voiced People on \x02%s\x0F" % chan)
                elif what == 'users':
                    protected = c['protected']
                    for user in channel.clients.copy():
                        if 'Q' in user.modes or ('R' in user.modes and user.nick == c['owner']) \
                            or ('R' in user.modes and user.nick in protected): continue
                        client.broadcast(channel.name, ':%s KICK %s %s :CLEAR USERS used by %s.' % \
                            (CS_IDENT, channel.name, user.nick, client.nick))
                        for op_list in channel.ops:
                            if user.nick in op_list: op_list.remove(user.nick)
                        user.channels.pop(channel.name)                        
                        channel.clients.remove(user)
                    if not len(channel.clients):
                        client.server.channels.pop(channel.name)
                    csmsg("Cleared users from \x02%s\x0F." % chan)
                else: csmsg("Unknown setting \x02%s\x0F." % what)

    elif cmd == 'owner':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax \x02OWNER \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ',1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if c.r:
                ops = c['operators']
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not channel:
                csmsg("%s is not currently in use." % chan)
            elif client.nick != c['owner'] or 'R' not in client.modes:
                csmsg("Access denied.")
            elif nick in channel.modes['q']:
                csmsg("%s is already an owner in %s." % (nick,chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(channel,'+q',nick)
                    csmsg("Owner status given to %s in %s." % (nick,chan))
                else: csmsg("%s is not on %s." % (nick,chan))

    elif cmd == 'deowner':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax \x02DEOWNER \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ',1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if c.r:
                ops = c['operators']
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not channel:
                csmsg("%s is not currently in use." % chan)
            elif client.nick != c['owner'] or 'R' not in client.modes:
                csmsg("Access denied.")
            elif nick not in channel.modes['q']:
                csmsg("%s is not an owner in %s." % (nick,chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(channel,'-q',nick)
                    csmsg("Owner status removed from %s in %s." % (nick,chan))
                else: csmsg("%s is not on %s." % (nick,chan))

    elif cmd == 'protect':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax \x02PROTECT \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ',1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if c.r:
                ops = c['operators']
                protected = c['protected']
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not 'R' in client.modes and not client.oper:
                csmsg("Access denied.")
            elif (client.nick not in ops and client.nick != c['owner']) \
                or (client.nick in ops and ops[client.nick] != 'a') and not client.oper:
                csmsg("Access denied.")
            elif nick in protected: csmsg("%s is already protected in \x02%s\x0F." % (nick,chan))
            else:
                db = cache['db']
                cur = db.cursor()
                cur.execute("SELECT * FROM %s WHERE nick=?" % NS_TABLE, (nick,))
                r = cur.fetchone()
                if not r: csmsg("\x02%s\x0F isn't registered." % nick)
                else:
                    c['protected:%s' % nick] = client.nick
                    csmsg("Protected %s in \x02%s\x0F." % (nick,chan))
                del db,cur,r

    elif cmd == 'deprotect':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax \x02DEPROTECT \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ',1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if c.r:
                ops = c['operators']
                protected = c['protected']
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not 'R' in client.modes and not client.oper:
                csmsg("Access denied.")
            elif (client.nick not in ops and client.nick != c['owner']) \
                or (client.nick in ops and ops[client.nick] != 'a') and not client.oper:
                csmsg("Access denied.")
            elif nick not in protected:
                csmsg("%s isn't in the list of protected users for \x02%s\x0F." % (nick,chan))
            else:
                del c['protected:%s' % nick]
                csmsg("Removed %s from the list of protected users for \x02%s\x0F." % (nick,chan))

    elif cmd == 'op':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax \x02OP \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ',1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if c.r:
                ops = c['operators']
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not channel:
                csmsg("%s is not currently in use." % chan)
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg("Access denied.")
            elif c['owner'] != client.nick and client.nick in ops \
                and (ops[client.nick] == 'v' or ops[client.nick] == 'h'):
                csmsg("Access denied.")
            elif nick in channel.modes['o']:
                csmsg("%s is already an operator in %s." % (nick,chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(channel,'+o',nick)
                    csmsg("Operator status given to %s in %s." % (nick,chan))
                else: csmsg("%s is not on %s." % (nick,chan))

    elif cmd == 'deop':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax \x02DEOP \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ',1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if c.r:
                ops = c['operators']
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not channel:
                csmsg("%s is not currently in use." % chan)
            elif not 'R' in client.modes: csmsg("Access denied. (Must be identified with services.)")
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg("Access denied.")
            elif client.nick in ops and (ops[client.nick] == 'v' or ops[client.nick] == 'h') \
                and c['owner'] != client.nick:
                csmsg("Access denied.")
            elif nick not in channel.modes['o']:
                csmsg("%s isn't an operator in %s." % (nick,chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(channel,'-o',nick)
                    csmsg("Removed operator status from %s in %s." % (nick,chan))
                else: csmsg("%s is not on %s." % (nick,chan))

    elif cmd == 'halfop':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax \x02HALFOP \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ',1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if c.r:
                ops = c['operators']
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not channel:
                csmsg("%s is not currently in use." % chan)
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg("Access denied.")
            elif c['owner'] != client.nick and client.nick in ops \
                and (ops[client.nick] == 'v' or ops[client.nick] == 'h'):
                csmsg("Access denied.")
            elif nick in channel.modes['h']:
                csmsg("%s is already a half-operator in %s." % (nick,chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(channel,'+h',nick)
                    csmsg("Half Operator status given to %s in %s." % (nick,chan))
                else: csmsg("%s is not on %s." % (nick,chan))

    elif cmd == 'dehalfop':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax \x02DEHALFOP \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ',1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if c.r:
                ops = c['operators']
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not channel:
                csmsg("%s is not currently in use." % chan)
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg("Access denied.")
            elif c['owner'] != client.nick and client.nick in ops \
                and (ops[client.nick] == 'v' or ops[client.nick] == 'h'):
                csmsg("Access denied.")
            elif nick not in channel.modes['h']:
                csmsg("%s isn't a half-operator in %s." % (nick,chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(channel,'-h',nick)
                    csmsg("Removed half operator status from %s in %s." % (nick,chan))
                else: csmsg("%s is not on %s." % (nick,chan))

    elif cmd == 'voice':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax \x02VOICE \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ',1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if c.r:
                ops = c['operators']
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not channel:
                csmsg("%s is not currently in use." % chan)
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg("Access denied.")
            elif client.nick in ops and ops[client.nick] == 'v' and c['owner'] != client.nick:
                csmsg("Access denied.")
            elif nick in channel.modes['v']:
                csmsg("%s is already voiced in %s." % (nick,chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(channel,'+o',nick)
                    csmsg("Voice given to %s in %s." % (nick,chan))
                else: csmsg("%s is not on %s." % (nick,chan))

    elif cmd == 'devoice':
        if not args or len(args.split(' ',1)) != 2:
            csmsg("Syntax \x02DEVOICE \x1Fchannel\x0F \x02\x1Fnick\x0F")
        else:
            chan, nick = args.split(' ',1)
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if c.r:
                ops = c['operators']
            if not c.r:
                csmsg("%s isn't registered." % chan)
            elif not channel:
                csmsg("%s is not currently in use." % chan)
            elif client.nick not in ops and c['owner'] != client.nick:
                csmsg("Access denied.")
            elif client.nick in ops and ops[client.nick] == 'v' and c['owner'] != client.nick:
                csmsg("Access denied.")
            elif nick not in channel.modes['v']:
                csmsg("%s isn't voiced in %s." % (nick,chan))
            else:
                user = [u for u in channel.clients if u.nick == nick]
                if user:
                    csmode(channel,'-v',nick)
                    csmsg("Voice removed from %s in %s." % (nick,chan))
                else: csmsg("%s is not on %s." % (nick,chan))

    elif cmd == 'invite':
        if not args: csmsg("Syntax: \x02/CHANSERV INVITE \x1Fchannel\x0F")
        elif not 'R' in client.modes: csmsg("Access denied.")
        else:
            c = Channel(args)
            channel = client.server.channels.get(args)
            if not c.r or not channel: csmsg("Channel \x02%s\x0F doesn't exist")
            elif 'i' not in channel.modes: csmsg("\x02%s\x0F is not +i.")
            else:
                o = c['operators']
                if client.nick != c['owner'] and client.nick != c['successor'] and \
                    (not client.nick in o or (client.nick in o and o[client.nick] == 'v')):
                    csmsg("Access denied.")
                elif 'i' in channel.modes and type(channel.modes['i']) == list:
                    channel.modes['i'].append(client.nick)

                    # Tell the channel
                    response = ':%s NOTICE @%s :%s invited %s into the channel.' % \
                        (CS_IDENT, channel.name, CS_IDENT.split('!')[0], client.nick)
                    client.broadcast(channel.name,response)

                    # Tell the invitee
                    response = ':%s INVITE %s :%s' % \
                    (CS_IDENT, client.nick, channel.name)
                    client.broadcast(client.nick,response)

    elif cmd == 'kick':
        if not args or not ' ' in args or len(args.split(' ',2)) != 3:
            csmsg("Usage: \x02/CHANSERV KICK \x1Fchannel\x0F \x02\x1Fnick\x0F \x02\x1Freason\x0F")
        else:
            channel_name, nick, reason = args.split(' ',2)
            c = Channel(channel_name)
            if not c.r: csmsg("\x02%s\x0F isn't registered." % channel_name)
            else:
                channel = client.server.channels.get(channel_name)
                if not channel: csmsg("%s no such channel." % channel_name)
                else:
                    chanops = c['operators']
                    if 'R' not in client.modes:
                        csmsg("Access denied. (Must be identified with services.)")
                    elif client.nick != c['owner'] and client.nick not in chanops:
                        csmsg("Access denied.")
                    elif client.nick in chanops and chanops[client.nick] == 'v':
                        csmsg("Access denied.")
                    elif c['peace']: csmsg("Access denied. (Peace.)")
                    else:
                        user = None
                        for i in channel.clients:
                            if i.nick == nick:
                                user = i
                                break
                        if not user: csmsg("\x02%s\x0F is not currently on channel %s" % (nick,channel_name))
                        else:
                            if 'Q' in user.modes: csmsg("Cannot kick %s. (+Q)" % nick)
                            else:
                                for op_list in channel.ops:
                                    if user.nick in op_list: op_list.remove(user.nick)
                                if c['signkick']: client.broadcast(channel.name, ':%s KICK %s %s :%s (%s)' % \
                                    (CS_IDENT, channel.name, user.nick, reason, client.nick))
                                else: client.broadcast(channel.name, ':%s KICK %s %s :%s' % \
                                    (CS_IDENT, channel.name, user.nick, reason))
                                user.channels.pop(channel.name)
                                channel.clients.remove(user)
            del c

    elif cmd == 'topic' or cmd == 'appendtopic':
        if not args or len(args.split(' ',1)) < 2: csmsg("Usage: \x02/CHANSERV TOPIC \x1Fchannel\x0F \x02\x1Ftopic\x0F")
        else:
            chan = args.split()[0]
            topic = params.split(' ',2)[2]
            c = Channel(chan)
            channel = client.server.channels.get(chan)
            if not c.r: csmsg("%s isn't registered." % chan)
            elif c['topiclock'] == 'on' and client.nick != c['owner']:
                csmsg("Topic of %s is locked." % chan)
            else:
                ops = c['operators']
                if not client.nick in ops and client.nick != c['owner'] and client.nick != c['successor']:
                    csmsg("You are not a channel operator.")
                elif client.nick in ops and ops[client.nick] == 'v':
                    csmsg("You are not a channel operator.")
                else:
                    if cmd == 'appendtopic':
                        if channel and channel.topic: topic = '%s %s' % (channel.topic,topic)
                        elif c['topic']: topic = '%s %s' % (c['topic'],topic)
                    if topic != c['topic']:
                        c['topic'] = topic
                        c['topic_by'] = client.nick
                        c['topic_time'] = str(time.time())[:10]
                        if not channel: csmsg("Stored topic for %s changed to \x02%s\x0F." % (chan, topic))
                    if channel and channel.topic != topic:
                        channel.topic = topic
                        channel.topic_time = str(time.time())[:10]
                        client.broadcast(channel.name,':%s TOPIC %s :%s' % (CS_IDENT, chan, topic))
                        csmsg("Topic of %s changed to \x02%s\x0F" % (chan,topic))
            del c

    elif cmd == 'list':
        if not args: csmsg("Usage \x02/CHANSERV LIST \x1Fpattern\x0F")
        else:
            if not client.oper or 'R' not in client.modes:
                csmsg("Access denied.")
            else:
                if not args.startswith('#') and not args.startswith('*'):
                    args = '#'+args
                args = escape(args.replace('*','%'))
                db = cache['db']
                c = db.cursor()
                c.execute("SELECT * FROM %s WHERE channel LIKE ?" % TABLE, (args,))
                t = c.fetchall()
                csmsg_list(t)
                del db,c,t

    elif cmd == 'info':
        if not args: csmsg("Usage: \x02/CHANSERV INFO \x1FCHANNEL\x0F")
        else:
            c = Channel(escape(args))
            if not c.r: csmsg("\x02%s\x0F isn't registered." % args)
            else: 
                channel = client.server.channels.get(args)
                bans = c['bans'].items()
                ops = c['operators']
                if channel:
                    csmsg(" \x02%s\x0F is active with %i client(s)" % (args, len(channel.clients)))
                else:
                    csmsg("\x02%s\x0F:" % args)
                if c['url']:
                    csmsg("            URL: %s" % c['url'])
                if channel:
                    csmsg("          Topic: %s" % channel.topic)
                csmsg("          About: %s" % c['description'])
                if client.oper and c['email']:
                    csmsg("         E-Mail: \x02%s\x0F" % c['email'])
                if client.oper or 'R' in client.modes:
                    csmsg("        Founder: %s" % c['owner'])
                csmsg("      Last used: %s" % fmt_timestamp(c['time_use']))
                csmsg("Time registered: %s" % fmt_timestamp(c['time_reg']))
                if bans:
                    if client.oper or ('R' in client.modes and client.nick == c['owner']) \
                        or ('R' in client.modes and client.nick in ops and ops[client.nick] != 'v'):
                        l = max([len(re_to_irc(i[0])) for i in bans])
                        csmsg("           Bans: \x02%s\x0F %s(%s)" % \
                            (re_to_irc(bans[0][0]), ' ' * int(l - len(re_to_irc(bans[0][0]))), bans[0][1]))
                        for index,(mask,setter) in enumerate(bans):
                            if index == 0: continue
                            mask = re_to_irc(mask)
                            csmsg(' '*17+'\x02%s\x0F %s(%s)' % (mask,' ' * int(l - len(mask)),setter))
            del c

    elif cmd == 'drop':
        if not args or not ' ' in args: csmsg("Usage: \x02/CHANSERV DROP \x1Fchannel\x0F \x02\x1Fpassword\x0F")
        else:
            channel_name,password = args.split()
            password = hashlib.sha1(password.encode('utf-8')).hexdigest()
            db = cache['db']
            c = db.cursor()
            c.execute("SELECT * FROM %s WHERE channel=?" % TABLE, (channel_name,))
            r = c.fetchone()
            if not r: csmsg("\x02%s\x0F isn't registered." % channel_name)
            else:
                # IRC Operators can supply anything as a password.
                if client.oper or (r['password'] == password):
                    c.execute("DELETE FROM %s WHERE channel=?" % TABLE, (channel_name,))
                    db.commit()
                    csmsg("Dropped \x02%s\x0F." % channel_name)
                    client.broadcast('umode:W',':%s NOTICE * :%s has dropped the channel \x02%s\x0F.' % \
                        (CS_IDENT, client.nick, channel_name))
                    channel = client.server.channels.get(channel_name)
                    if channel and 'R' in channel.modes:
                        del channel.modes['R']
                        client.broadcast(channel_name, ":%s MODE %s -R" % \
                            (CS_IDENT,channel_name))
                else:
                    csmsg("Incorrect password.")
                    warn = ":%s NOTICE * :\x034WARNING\x0F :%s tried to drop %s with an incorrect password." % \
                        (CS_IDENT, client.nick, nick)
                    client.broadcast('umode:W', warn)
            del db,c,r

    elif cmd == "expire":
        if not client.oper:
            csmsg("Unknown command.")
            csmsg("Use \x02/CHANSERV HELP\x0F for a list of available commands.")
        else:
            db = cache['db']
            c = db.cursor()
            c.execute("SELECT * FROM %s" % TABLE)
            t = c.fetchall()
            for r in t:
                if is_expired(r['time_use']):
                    csmsg("\x02%s\x0F has expired due to inactivity." % r['channel'])
                    client.broadcast('umode:W',':%s NOTICE * :%s expired \x02%s\x0F.' % \
                        (CS_IDENT, client.nick, r['channel']))
                    c.execute("DELETE FROM %s WHERE channel=?" % TABLE, (r['channel'],))
            db.commit()
            csmsg("All registrations have been cycled through.")
            del db,c,r,t

    elif cmd == "xyzzy":
        c = Channel(args)
        if c.r and client.oper:
            csmsg(c)
            for i in c.keys(): csmsg('%s: %s' % (i,c[i]))
            csmsg("")
        csmsg("Nothing happens.")
        if c.r and client.oper: csmsg("")
        del c

    else:
        csmsg("Unknown command.")
        csmsg("Use \x02/CHANSERV HELP\x0F for a list of available commands.")

