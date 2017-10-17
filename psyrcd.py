#!/usr/bin/env python3
# _*_ coding: UTF-8 _*_

# psyrcd the Psybernetics IRC server.
# Based on hircd.py. Modifications have been added for robustness and flexibility.
# Gratitude to Ferry Boender for starting this off
# http://www.electricmonk.nl/log/2009/09/14/hircd-minimal-irc-server-in-python/

# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Todo:
#   - Check the PID file on startup. Issue a warning and raise SystemExit 
#     if psyrcd is already running.
#   - Implement /userhost
#   - Implement all user and channel modes.
#   - Fix TODO comments.
# Scripting:
#   - /operserv scripts                      Lists all loaded scripts.
#   - /operserv scripts list                 Lists all available scripts.
#   - /operserv scripts load scriptname      
#
#      Loads the specified file as a code object using a specific namespace,
#      where a variable called 'init' is set to True.
#
#   - /operserv scripts unload scriptname 
#
#      Unloads the specified file by executing its code object with
#      'init' set to False. This indicates that file handles in
#      the cache must be closed and structures on affected objects
#      ought to be removed.
#
#   Have a look at the doc/SCRIPTING.MD file to see some tips on creating
#   channel modes.
#
# Known Errors:
#   - Windows doesn't have fork(). Run in the foreground or Cygwin.

from concurrent.futures import ThreadPoolExecutor
import sys, os, re, pwd, time, argparse, importlib, logging, hashlib, asyncio, socket, ssl, json

try:
    import uvloop # https://github.com/MagicStack/uvloop
except ImportError:
    uvloop = None

import hcl
import pluginbase

# These constants enable the IRCD to function without a configuration file:
SRV_VERSION     = "psyrcd-2.0.0"
NET_NAME        = "psyrcd-dev"
SRV_DOMAIN      = "irc.psybernetics.org"
SRV_DESCRIPTION = "I fought the lol, and. The lol won."
SRV_WELCOME     = "Welcome to %s" % NET_NAME
SRV_CREATED     = time.asctime()

MAX_CLIENTS    = 8192 # User connections to be permitted before we start denying new connections.
MAX_IDLE       = 300  # Time in seconds a user may be caught being idle for.
MAX_NICKLEN    = 12   # Characters per available nickname.
MAX_CHANNELS   = 200  # Channels per server on the network.
MAX_TOPICLEN   = 512  # Characters per channel topic.
PING_FREQUENCY = 120  # Time in seconds between PING messages to clients.

OPER_USERNAME = os.environ.get('USER', None)
OPER_PASSWORD = True    # Set to True to generate a random password, False to
                        # disable the oper system, a string of your choice or
                        # pipe at runtime: openssl rand -base64 32 | psyrcd -f
# IRC numerics by name
RPL_WELCOME           = '001'
RPL_YOURHOST          = '002'
RPL_CREATED           = '003'
RPL_MYINFO            = '004'
RPL_ISUPPORT          = '005'
RPL_UMODEIS           = '221'
RPL_LUSEROP           = '252'
RPL_LUSERCHANNELS     = '254'
RPL_LUSERME           = '255'
RPL_WHOISUSER         = '311'
RPL_WHOISSERVER       = '312'
RPL_WHOISOPERATOR     = '313'
RPL_ENDOFWHO          = '315'
RPL_WHOISIDLE         = '317'
RPL_ENDOFWHOIS        = '318'
RPL_WHOISCHANNELS     = '319'
RPL_WHOISSPECIAL      = '320'
RPL_LISTSTART         = '321'
RPL_LIST              = '322'
RPL_LISTEND           = '323'
RPL_TOPIC             = '332'
RPL_TOPICWHOTIME      = '333'
RPL_WHOISBOT          = '335'
RPL_INVITING          = '341'
RPL_EXCEPTLIST        = '348'
RPL_ENDOFEXCEPTLIST   = '349'
RPL_WHOREPLY          = '352'
RPL_BANLIST           = '367'
RPL_ENDOFBANLIST      = '368'
RPL_HOSTHIDDEN        = '396'
ERR_NOSUCHNICK        = '401'
ERR_NOSUCHCHANNEL     = '403'
ERR_CANNOTSENDTOCHAN  = '404'
ERR_UNKNOWNCOMMAND    = '421'
ERR_ERRONEUSNICKNAME  = '432'
ERR_NICKNAMEINUSE     = '433'
ERR_NOTONCHANNEL      = '442'
ERR_NOTIMPLEMENTED    = '449'
ERR_NOTFORHALFOPS     = '460'
ERR_NEEDMOREPARAMS    = '461'
ERR_UNKNOWNMODE       = '472'
ERR_INVITEONLYCHAN    = '473'
ERR_BANNEDFROMCHAN    = '474'
ERR_BADCHANNELKEY     = '475'
ERR_CHANOPPRIVSNEEDED = '482'
ERR_VOICENEEDED       = '489'
ERR_CHANOWNPRIVNEEDED = '499'
RPL_WHOISSECURE       = '671'

class IRCError(Exception):
    """
    Exception thrown by IRC command handlers to notify client of a server/client error.
    """
    def __init__(self, code, value):
        self.code  = code
        self.value = value

    def __str__(self):
        return(repr(self.value))

class IRCChannel(object):
    """
    Object representing an IRC channel.
    """
    def __init__(self, name, topic=''):
        self.name = name
        self.topic_by = name
        self.topic_time = str(time.time())[:10]
        self.topic = topic
        self.clients = set()
        self.supported_modes = {  # Uppercase modes can only be set and removed by opers.
            'A':"Server administrators only.",
            'i':"Invite only.",
            'm':"Muted.",
            'n':"No messages allowed from users who are not in the channel.",
            'g':"Hide channel operators.",
            'v':"Voiced. Cannot be muted.",
            'h':"Channel half-operators.",
            'o':"Channel operators.",
            'a':"Channel administrators.",
            'q':"Channel owners.",
            'b':"Channel bans.",
            'e':"Exceptions to channel bans.",
            'O':"Server operators only.",
            'p':"Private. Hides channel from /whois.",
            'r':"[redacted] Redacts usernames and replaces them with the first word in this line.",
#            'l':"Limited amount of users.",
            'k':"Password protected.",
            's':"Secret. Hides channel from /list.",
            't':"Only operators may set the channel topic.",
#            'z':"Only allow clients connected via SSL.",
        }
        self.modes = {
            'n': 1,
            't': 1,
            'v': [],
            'h': [],
            'o': [],
            'a': [],
            'q': [],
            'b': [],
            'e': []
        }
        self.ops = [self.modes['v'],self.modes['h'],self.modes['o'],self.modes['a'],self.modes['q']]
#     # modes['b'] ==> 'mask_regex setter_nick unix_time' -> i.split()[0]
    def __repr__(self): return('<%s %s at %s>' % (
        self.__class__.__name__,
        self.name,
        hex(id(self))
        )
    )

class IRCOperator(object):
    """
    Object holding stateful info and commands relevant to policing the server from inside.
    """
    def __init__(self, client):
        self.client = client    # So we can access everything relavent to this oper
        self.vhost = "internet"
        self.modes = ['O','Q','S','W'] # Set on client once authed
        self.passwd = None

    def dispatch(self,params):
        """
        Handler for IRCop specific commands.
        """
        try:
            response = ''
            if ' ' in params:
                command, params = params.split(' ', 1)
                handler = getattr(self, 'handle_%s' % (command.lower()))
            else:
                command = None
                handler = getattr(self, 'handle_%s' % (params.lower()))
            response = handler(params)
            return response
        except Exception as e:
            return 'Internal Error: %s' % e

    def handle_seval(self, params):
        if 'A' in self.client.modes:
            message = ': %s' % (eval(params))
            return message

    def handle_setkey(self, params):
        """
        Defines the passphrase a foreign server must transmit to us in order to synchronise a link.
        Linking is disabled by default until a local passphrase is defined.
        /operserv setkey server-link-passphrase
        """
        if not "N" in self.client.modes:
            return ": Network Administrators only."

        if not params or len(params) < 40:
            return ": Error: New link keys must be at least 40 characters in length."

        self.client.server.link_key = params.split()[0]
        self.client.broadcast("umode:W", ":%s NOTICE * :%s has updated the link key for %s." % \
            (SRV_DOMAIN, self.client.client_ident(True), SRV_DOMAIN))

    def handle_getkey(self, params):
        """
        This command permits Network Administrators to obtain the active server
        link key for the host they're connected to.
        """
        if not "N" in self.client.modes:
            return ": Network Administrators only."
        
        self.client.write(self.client.server.link_key)

    def handle_slink(self, params):
        """
        Connect to another instance of psyrcd and attempt to synchronise objects.
        /operserv slink hostname[:port] remote-passphrase
        """
        if not "N" in self.client.modes:
            return ": Network Administrators only."
        if not ' ' in params or len(params.split()) != 2:
            self.client.write("Usage: OPERSERV SLINK rhost:port link_key")
            return
        rhost, link_key = params.split(" ", 1)
        self.client.server.link_server(self.client, rhost, link_key)

    def handle_squit(self, params):
        """
        Disconnect a instance of psyrcd and clean up.
        /operserv squit hostname[:port]
        """
        if not "N" in self.client.modes:
            return ": Network Administrators only."
        
        if not params or params.lower() == "squit":
            self.client.write("Usage: OPERSERV SQUIT <RHOST>")
            return
        return self.client.server.unlink_server(self.client, params)

    def handle_dump(self, params):
        """
        Dump internal server info for debugging.
        """
        # TODO: Phase this out in favour of /stats
        # TODO: Show modes, invites, excepts, bans.
        response = ':%s NOTICE %s :Clients: %s' % \
            (SRV_DOMAIN, self.client.nick, self.client.server.clients)
        self.client.broadcast(self.client.nick, response)
        
        for client in self.client.server.clients.values():
            response = ':%s NOTICE %s :  %s' % \
                (SRV_DOMAIN, self.client.nick, client)
            self.client.broadcast(self.client.nick, response)
            
            for channel in client.channels.values():
                response = ':%s NOTICE %s :    %s' % \
                    (SRV_DOMAIN, self.client.nick, channel.name)
                self.client.broadcast(self.client.nick, response)
        response = ':%s NOTICE %s :Channels: %s' % \
            (SRV_DOMAIN, self.client.nick, self.client.server.channels)
        self.client.broadcast(self.client.nick, response)
        for channel in self.client.server.channels.values():
            response = ':%s NOTICE %s :  %s %s' % \
                (SRV_DOMAIN, self.client.nick, channel.name, channel)
            self.client.broadcast(self.client.nick, response)
            for client in channel.clients:
                response = ':%s NOTICE %s :    %s %s' % \
                    (SRV_DOMAIN, self.client.nick, client.nick, client)
                self.client.broadcast(self.client.nick,response)

    def handle_addoper(self,params):
        """
        Handles adding another serverwide oper.
        Usage: /operserv addoper oper_name passwd
        """
        nick, password = params.split(' ', 1)
        user = self.client.server.clients.get(nick)
        if not user:
            return (':%s NOTICE %s : Invalid user.' % \
                (SRV_DOMAIN, self.client.nick))
        self.client.server.opers[user.nick] = IRCOperator(user)
        oper = self.client.server.opers.get(user.nick)
        if password:
            oper.passwd = hashlib.sha512(password).hexdigest()
        response = ':%s NOTICE %s :Created an oper account for %s.' % \
            (SRV_DOMAIN, self.client.nick, user.nick)
        self.client.broadcast(self.client.nick, response)

    def handle_plugins(self, params):
        if not 'A' in self.client.modes:
            return ": IRC Administrators only."
        return ": Unimplemented."

    def handle_scripts(self, params):
        """
        List, Load and Unload serverside scripts.

        Use "/operserv scripts" to display the current state of the system.
        Use "/operserv scripts list" to list the status of available scripts.
        Use "/operserv scripts load filename" & "/operserv scripts unload filename"
        for loading and unloading scripts.
        """
        if not 'A' in self.client.modes:
            return ": IRC Administrators only."
        if ' ' in params:
            cmd, args = params.split(' ', 1)
        else:
            cmd = params
            args = ''
        
        s = self.client.server.scripts
        
        # /operserv scripts (list what's loaded)
        if cmd == 'scripts':
            tmp=data=[]
            for type, array in s.i.items():
                for name, script in array.items():
                    tmp = {}
                    if type == 'commands':
                        tmp['Name'] = '/'+name
                    if type == 'umodes':
                        tmp['Name'] = 'umode:'+name
                    if type == 'cmodes':
                        tmp['Name'] = 'cmode:'+name
                    tmp['Descripton'] = script[1]
                    tmp['File'] = script[0].file.split(os.path.sep)[-1]
                    
                    if not options.debug:
                        f    = open(script[0].file,'r')
                        hash = sha1sum(f.read())
                        f.close()
                        # Add an asterisk next to the filename if modified.
                        if hash != script[0].hash:
                            tmp['File'] = tmp['File'] + '*'
                    tmp['Hash'] = script[0].hash
                    data.append(tmp)
            
            fmt   = format(data)
            table = tabulate(fmt, ul='-')(data)
            if not table:
                table = "There are no scripts loaded."
            for line in table.split('\n'):
                self.client.write(line)
            del fmt, table, data, tmp
        
        # /operserv scripts list (list what's available)
        elif cmd == 'list':
            data=[]
            if s.dir:
                files = os.listdir(s.dir)
                for filename in files:
                    if os.path.isdir(s.dir+filename): continue
                    tmp={}
                    tmp['File'] = filename
                    tmp['State'] = 'UNLOADED'
                    for type, array in s.i.items():
                        for name, script in array.items():
                            if script[0].file.split(os.path.sep)[-1] == filename:
                                tmp['State'] = 'LOADED'
                                break
                    data.append(tmp)
                fmt   = format(data)
                table = tabulate(fmt, ul='-')(data)
                if not table:
                    table = "There are no scripts in %s." % s.dir
                for line in table.split('\n'):
                    self.client.write(line)
                del fmt, table, data, tmp
            else:
                self.client.write('A nonexistent path was defined as the scripts directory.')
        
        elif cmd == 'load':
            s.load(args, self.client)
        
        elif cmd == 'unload':
            s.unload(args, self.client)

    def handle_sajoin(self, params):
        """
        Permits an IRC Operator to force a client to JOIN a channel.
        """
        target, channel = params.split()
        victim = self.client.server.clients.get(target)
        if victim: victim.handle_join(channel)

    def handle_sapart(self, params):
        """
        Permits an IRC Operator to force a client to PART a channel.
        """
        target, channel = params.split()
        victim = self.client.server.clients.get(target)
        if victim: victim.handle_part(channel)

class Line(object):
    """
    Line is for easily parsing the input lines that produce ScriptContexts.
    """
    def __init__(self, line):
        self.body = line
        self.time = time.time()

    def split(self):
        return self.body.split()

    @property
    def nick(self):
        return None

    @property
    def host(self):
        return None

    @property
    def channel(self):
        return None

    def __str__(self):
        return self.body

    def __repr__(self):
        return "<Line \"%s\" at %s>" % (self.body, hex(id(self)))

class ScriptContext(dict):
    """
    Load / Unload
        {"init": bool, "server": IRCServer}

    Commands:
        {"client": client, "line": line}

    Client modes:
        {"client": client, "mode": mode,
         "params": params, "func": func}

    Channel modes:
        {"client": client, "channel": channel, "line": line, "mode": mode,
         "func": func}

    This class is used instead of the plain dictionaries that were
    used previously to automatically provide instances of Line when a lookup
    is made for the value of `line` from within scripts and plugins.

    Given that setting the value for `line` automatically creates an instance
    of Line it should be possible to substitute for a plain Python string
    when calling scripted commands, i.e.: command({"client": self, "line": line})
    is equivalent to command(ctx).
    """
    def __init__(self, *args, **kwargs):
        self.cancelled = False
        
        if "line" in kwargs:
            kwargs["line"] = Line(kwargs["line"])
       
        dict.__init__(self, *args, **kwargs)

    def write(self, *args, msgprefix=":%s NOTICE" % SRV_DOMAIN):
        response = msgprefix
        for idx, word in enumerate(args):
            if not idx:
                response += " " + word + " :"
                continue
            response += word + " "
        return response

    @property
    def cancel(self):
        return "cancel" in self and self["cancel"]

    @cancel.setter
    def cancel(self, value):
        self["cancel"] = value

    def __getattr__(self, attr):
        if not attr.startswith("_") and attr in self:
            return self[attr]
        raise AttributeError

    def __setattr__(self, key, value):
        if key == "line":
            value = Line(value)
        super(ScriptContext, self).__setattr__(key, value) 

def scripts(func):
    def wrapper(self, *args, **kwargs):

        # Comment out the following line if you want to
        # script the commands executed on connect.
        if not self.user: return(func(self, *args))

        s = self.server.scripts
        p = self.server.plugins

        ctx = ScriptContext({'client': self, 'func': func})

        params = ctx["params"] = str(args[0]) if args else str()
        
        # Practically all client connection messages run through here.
        for mode in self.modes.copy():
            # This lets external components know why they're being invoked.
            ctx["mode"] = mode
            
            # Check for matching scripts.
            if mode in s.umodes:
                script = s.umodes[mode][0]
                try:
                    script.execute(ctx)
                    if 'cancel' in script.env:
                        return
                    if 'params' in script.env:
                        args = (script['params'],)
                except Exception as err:
                    logging.error('%s in %s' % (err,script.file))
                    self.broadcast('umode:W',':%s ERROR %s found %s in %s' % \
                        (SRV_DOMAIN,self.client_ident(), err, script.file))
            
            # Check for matching plugins.
            if mode in p.umodes:
                plugin = p.umodes[mode]
                try:
                    plugin(ctx)
                    if ctx.cancel:
                        return
                    if "params" in ctx:
                        args = (ctx["params"],)
                except Exception as err:
                    logging.error('%s in %s' % (err, plugin))
                    self.broadcast('umode:W',':%s ERROR %s found %s in %s' % \
                        (SRV_DOMAIN, self.client_ident(), err, plugin))

        if params.startswith('#'):
            if ' ' in params:
                channel = self.server.channels.get(params.split()[0])
            else:
                channel = self.server.channels.get(params)
            if channel:
                for mode in channel.modes.copy():
                    params = str()
                    if args:
                        params = str(args[0])
                    
                    if mode in s.cmodes:
                        script = s.cmodes[mode][0]
                        
                        ctx = ScriptContext({'client':  self,
                                             'channel': channel,
                                             'line':    params,
                                             'mode':    mode,
                                             'func':    func})
                        
                        try:
                            script.execute(ctx)
                            
                            if 'cancel' in s.env:
                                if isinstance(script['cancel'], (str, bytes)):
                                    return(script['cancel'])
                                else:
                                    return('')
                            if 'params' in script.env:
                                args = (script['params'],)
                        except Exception as err:
                            logging.error('%s in %s' % (err, script.file))
                            self.broadcast('umode:W',':%s ERROR %s found %s in %s' % \
                                (SRV_DOMAIN,self.client_ident(), err, script.file))
        return func(self, *args)
    
    wrapper.__doc__ = func.__doc__
    return(wrapper)

def disabled(func):
    def wrapper(self, *args):
#        command = func.func_name.strip('handle_').upper()
#        return(':%s is not available on this server.' % command)
        return('')
    return(wrapper)

def links(func):
    def wrapper(self, *args, **kwargs):
        for link in self.server.links.values():
            link[2].write(str(args))
        return(func(self, *args))
    wrapper.__doc__ = func.__doc__
    return(wrapper)

class IRCClient(object):
    """
    IRC client connect and command handling. Client connection is handled by
    the `handle` method which sets up a two-way communication with the client.
    It then handles commands sent by the client by dispatching them to the
    handle_ methods.
    """
    def __init__(self, server, sock, host):
        self.connected_at       = str(time.time())[:10] 
        self.server             = server
        self.request            = sock
        self.last_activity      = time.time()          # Subtract from time.time() to determine idle time
        self.user               = None                 # The part before the @
        self.realname           = None                 # Clients' real name
        self.nick               = None                 # Clients' currently registered nickname
        self.vhost              = None                 # Alternative hostmask for WHOIS requests
        self.send_queue         = []                   # Messages to send to client (strings)
        self.channels           = {}                   # Channels the client is in
        self.oper               = None                 # Assign an IRCOperator object if user opers up
        self.remote             = False                # User is known to us through a server link
        self.host               = host                 # Client's hostname / ip.
        self.rhost              = lookup(self.host[0]) # This users rdns. May return None.
        self.modes              = {'x':1}              # Usermodes set on the client
        self.supported_modes    = {                    # Uppercase modes are oper-only
            'A':"IRC Administrator.",
#           'b':"Bot.",
            'D':"Deaf. User does not recieve channel messages.",
            'H':"Hide ircop line in /whois.",
#           'I':"Invisible. Doesn't appear in /whois, /who, /names, doesn't appear to /join, /part or /quit",
            'L':"Connection is a remote server link.",
            'N':"Network Administrator.",
            'O':"IRC Operator.",
#           'P':"Protected. Blocks users from kicking, killing, or deoping the user.",
#           'p':"Hidden Channels. Hides the channels line in the users /whois",
            'Q':"Kick Block. Cannot be /kicked from channels.",
            'S':"See Hidden Channels. Allows the IRC operator to see +p and +s channels in /list",
            'W':"Wallops. Recieve connect, disconnect and traceback notices.",
#           'X':"Whois Notification. Allows the IRC operator to see when users /whois him or her.",
            'x':"Masked hostname. Hides the users hostname or IP address from other users.",
            'Z':"SSL connection."
        }

        # Keeps the hostmask unique which keeps bans functioning:
        host = self.host[0].encode('utf-8')
        self.hostmask = hashlib.new('sha512', host).hexdigest()[:len(host)]
        logging.info('Client connected: %s' % self.host[0])

        # TODO: Recognise other SSL handshakes.
        try:
            if re.match(b'\x16\x03[\x00-\x03]..\x01', self.request.recv(16, socket.MSG_PEEK)):
                logging.info('%s is using SSL.' % self.host[0])
                if options.ssl_cert and options.ssl_key:
                    # SSL client connections are blocking and thus get their
                    # own thread.
                    self.request.setblocking(1)
                    self.request = ssl.wrap_socket(self.request,
                                     server_side=True,
                                     certfile=options.ssl_cert,
                                     keyfile=options.ssl_key,
                                     ssl_version=ssl.PROTOCOL_SSLv23,
                                     ca_certs=None,
                                     do_handshake_on_connect=True,
                                     suppress_ragged_eofs=True,
                                     ciphers=None)
                    self.modes['Z'] = 1
                else: self.request.close()
        except BlockingIOError as err:
            if options.debug:
                logging.debug("BlockingIOError: %s." % err)

        # Check the server isn't full.
        if len(self.server.clients) >= MAX_CLIENTS:
            self.request.send(': MAX_CLIENTS exceeded.\n'.encode('utf-8'))
            self.request.close()
            logging.info('Connection refused to %s: MAX_CLIENTS exceeded.' % self.client_ident())

        # Check this host isn't K:Lined.
        for line, attributes in self.server.lines['K'].items():
            if re.match(line, self.host[0]):
                self.request.send(': This host is K:Lined. Reason: %s\n'.encode('utf-8') % attributes[2])
                self.request.close()
                logging.info('Connection refused to %s: K:Lined. (%s)' % (self.client_ident(), attributes[2]))
       
        if not 'Z' in self.modes:
            asyncio.Task(self.asyncio_reader())
        else:
            future = ThreadPool.submit(self.thread_reader)
            asyncio.wait(future, return_when=asyncio.ALL_COMPLETED)

    def asyncio_reader(self):
        """
        Container for iterating the coroutine responsible for a plaintext
        connection.
        """
        try:
            yield from self._handle()
        except IOError as err:
            pass
        finally:
            self.finish()

    def _handle(self):
        """
        Lower part of asyncio_reader.
        """
        while True:
            buf = yield from self.server.loop.sock_recv(self.request, 1024)
            self.handle(buf)

    def thread_reader(self):
        """
        thread_reader is for recv() calls on blocking connections without
        confusing the interpreter with `yield from`.
        Specifically it's for SSL connections.
        """
        while True:
            buf = self.request.recv(1024)
            self.handle(buf)

    def handle(self, buf):
        """
        The nucleus of the IRCD.
        """
        # Receive from the client and turn the data into line-oriented
        # output.
        if buf == b'':
            return
        
        buf = buf.decode('utf-8')

        while buf.find(u"\n") != -1:
            line, buf = buf.split("\n", 1)
            line = line.rstrip()

            handler = response = ''
            try:
                if ' ' in line:
                    command, params = line.split(' ', 1)
                else:
                    command = line
                    params = ''
                logging.info('from %s: %s' % (self.client_ident(),
                    ' '.join([command.upper(), params])))
                # The following checks if a command is in Scripts.commands
                # and calls its __call__ method, allowing scripts to replace
                # built-in commands.
                script = self.server.scripts.commands.get(command.lower())
                plugin = self.server.plugins.commands.get(command.lower())
                if script:
                    # "handler" has to be defined or we'll assume the command
                    # wasn't found, later.
                    handler = script[0]
                    try:
                        response = handler(self, command, params)
                    except Exception as e:
                        logging.error(e)
                        response = None
                elif plugin:
                    if "read_on_exec" in plugin and plugin["read_on_exec"]:
                        self.server.plugins.load(plugin.module_name)
                        plugin = self.server.plugins.commands.get(command.lower())
                    handler = plugin
                    ctx = ScriptContext(
                        cache=plugin["cache"],
                        client=self,
                        line=" ".join((command, params)),
                    )
                    response = handler(ctx)
                    if not response:
                        response = ""
                else:
                    handler = getattr(self, 'handle_%s' % (command.lower()), None)
                    if handler:
                        response = handler(params)
                
                if not handler:
                    logging.info('No handler for command: %s. Full line: %s' % (command, line))
                    raise IRCError(ERR_UNKNOWNCOMMAND, ':%s Unknown command' % command.upper())
            
            except AttributeError as err:
                response = ':%s ERROR :%s %s' % (self.server.config.server.domain, self.client_ident(), err)
                self.broadcast('umode:W', response)
                logging.error(err)
            
            except IRCError as err:
                response = ':%s %s %s %s' % (self.server.config.server.domain, err.code, self.nick, err.value)
                logging.error('%s' % (response))
            
            # It helps to comment the following exception when debugging
            except Exception as err:
                response = ':%s ERROR :%s %s' % (self.server.config.server.domain, self.client_ident(), err)
                self.broadcast('umode:W', response)
                self.broadcast(self.nick, response)
                logging.error(err)

            if response:
                logging.info('to %s: %s' % (self.client_ident(), response))
                self.request.send(response.encode("utf-8") + '\r\n'.encode("utf-8"))

#        self.request.close()

    @links
    def broadcast(self, target, message):
        """
        Handle message dispatch to clients.
        """
        # We log direct messages to clients when caught by * but channel and
        # privmsgs benefit from the speed improvement brought by keeping
        # confidence.
        message = message.encode("utf-8") + '\n'.encode("utf-8")
        if target == '*':
            [client.request.send(message) for client in self.server.clients.values()]
            [logging.debug('to %s: %s' % (client.client_ident(),
                message.decode("utf-8").strip("\n"))) \
                for client in self.server.clients.values()]

        elif target.startswith('#'):
            channel = self.server.channels.get(target)
            if channel:
                [client.request.send(message) for client in channel.clients if \
                    not 'D' in client.modes]
        
        elif target.startswith('ident:'):
            rhost = re_to_irc(target.split(':')[1],False)
            [client.request.send(message) for client in self.server.clients.values() \
                if re.match(rhost, c.client_ident(True))]
        
        elif target.startswith('umode:'):
            umodes = target.split(':')[1]
            for client in self.server.clients.values():
                if umodes in client.modes: client.request.send(message)
                else:
                    for mode in umodes:
                        if mode in client.modes:
                            client.request.send(message)
                            break
        
        elif target.startswith('cmode:'):
            cmodes = target.split(':')[1]
            for channel in self.server.channels.values():
                if cmodes in channel.modes:
                    for client in channel.clients:
                        client.request.send(message)
                    break
                else:
                    for mode in cmodes:
                        if mode in channel.modes:
                            for client in channel.clients:
                                client.request.send(message)
                            break
        
        else:
            client = self.server.clients.get(target)
            if client:
                try:
                    client.request.send(message)
                except IOError:
                    client.finish()
           
    # NOTE: Unsightly use of `SRV_DOMAIN` global in format string:
    def write(self, *params, msgprefix=":%s NOTICE " % SRV_DOMAIN):
        """
        Quickly transmit server notices to client connections.
        """
        for msg in map(str, params):
            for line in msg.splitlines():
                if self in self.server.clients.values():
                    self.request.send(bytes('{0}{1} :{2}\n'
                        .format(msgprefix, self.nick, line).encode('utf-8')))
                else:
                    client = self.server.clients.get(self.nick)
                    if client:
                        client.send_queue.append('%s%s :%s' % \
                            (msgprefix, self.nick, line))

    @links
    @scripts
    def handle_privmsg(self, params):
        """
        Handle sending a private message to a user or channel.
        """
        self.last_activity = str(time.time())[:10] 
        if not ' ' in params or not self.nick or \
            not self.user or not self.realname:
            raise IRCError(ERR_NEEDMOREPARAMS, ':PRIVMSG Not enough parameters')
        
        target, msg = params.split(' ', 1)
        message = ':%s PRIVMSG %s %s' % (self.client_ident(), target, msg)
        
        if target.startswith('#'):
            # Message to channel. Check if the channel exists.
            channel = self.server.channels.get(target)
            if channel:
                if not channel.name in self.channels:
                    # The user isn't in the channel.
                    raise IRCError(ERR_CANNOTSENDTOCHAN, '%s :Cannot send to channel' % (channel.name))
                
                if 'm' in channel.modes:
                    if self.nick not in channel.modes['v'] and self.nick not in channel.modes['h'] \
                    and self.nick not in channel.modes['o'] and self.nick not in channel.modes['a'] \
                    and self.nick not in channel.modes['q'] and not self.oper:
                        raise IRCError(ERR_VOICENEEDED, '%s :%s is +m.' % (channel.name, channel.name))
                
                if 'r' in channel.modes:
                    message = ':%s PRIVMSG %s %s' % (channel.supported_modes['r'].split()[0], target, msg)
                
                for client in channel.clients:
                    if client != self and not 'D' in client.modes:
                        self.broadcast(client.nick, message)
            else:
                raise IRCError(ERR_NOSUCHNICK, '%s' % target)
        else:
            # Message to user
            client = self.server.clients.get(target, None)
            if client: self.broadcast(client.nick,message)
            else: raise IRCError(ERR_NOSUCHNICK, '%s' % target)

    @links
    @scripts
    def handle_notice(self, params):
        """
        Handle sending a notice to a user or channel.
        """
        # The reason this doesn't call handle_privmsg specifying that it's a
        # NOTICE is because of the way the @scripts decorator locks default
        # arguments in.
        self.last_activity = str(time.time())[:10] 
        if not ' ' in params:
            raise IRCError(ERR_NEEDMOREPARAMS, ':NOTICE Not enough parameters')
        
        target, msg = params.split(' ', 1)
        message = ':%s NOTICE %s %s' % (self.client_ident(), target, msg)
        if target.startswith('#'):
            # Message to channel. Check if the channel exists.
            channel = self.server.channels.get(target)
            if channel:
                if not channel.name in self.channels:
                    # The user isn't in the channel.
                    raise IRCError(ERR_CANNOTSENDTOCHAN, '%s :Cannot send to channel' % (channel.name))
                
                if 'm' in channel.modes:
                    if self.nick not in channel.modes['v'] and self.nick not in channel.modes['h'] \
                    and self.nick not in channel.modes['o'] and self.nick not in channel.modes['a'] \
                    and self.nick not in channel.modes['q'] and not self.oper:
                        raise IRCError(ERR_VOICENEEDED, '%s :%s is +m.' % (channel.name, channel.name))
                
                if 'r' in channel.modes:
                    message = ':%s NOTICE %s %s' % (channel.supported_modes['r'].split()[0], target, msg)
                
                for client in channel.clients:
                    if client != self and not 'D' in client.modes:
                        self.broadcast(client.nick, message)
            else:
                raise IRCError(ERR_NOSUCHNICK, '%s' % target)
        else:
            # Message to user
            client = self.server.clients.get(target, None)
            if client:
                self.broadcast(client.nick,message)
            else:
                raise IRCError(ERR_NOSUCHNICK, '%s' % target)

    @links
    @scripts
    def handle_nick(self, params):
        """
        Handle the initial setting of the user's nickname and nick changes.
        """
        self.last_activity = str(time.time())[:10] 
        nick = params
        # Valid nickname?
        if re.search('[^a-zA-Z0-9\-\[\]\'`^{}_]', nick) or len(nick) > MAX_NICKLEN:
            raise IRCError(ERR_ERRONEUSNICKNAME, ':%s' % (nick))

        # Doesn't overlap with anyone else already here?
        for i in self.server.clients.keys():
            if nick.lower() == i.lower():
                raise IRCError(ERR_NICKNAMEINUSE, 'NICK :%s' % nick)

        # New connection
        if not self.nick:
            self.nick = nick
            self.server.clients[nick] = self
            self.broadcast(self.nick, ':%s %s %s :%s' % \
                 (self.server.servername, RPL_WELCOME, self.nick, SRV_WELCOME))
            self.broadcast(self.nick, ':%s %s %s :Your host is %s, running version %s' % \
                (self.server.servername, RPL_YOURHOST, self.nick, self.server.config.server.domain, SRV_VERSION))
            self.broadcast(self.nick, ':%s %s %s :This server was created %s' % \
                (self.server.servername, RPL_CREATED, self.nick,SRV_CREATED))
            # opers, channels, clients and MOTD
            self.handle_lusers(None)
            self.handle_motd(None)
            # Hostmasking
            self.broadcast(self.nick, ':%s %s %s %s :is now your displayed host' % \
                (self.server.config.server.domain, RPL_HOSTHIDDEN, self.nick, self.hostmask))
            if self.modes:
                self.broadcast(self.nick, ':%s MODE %s +%s' % \
                    (self.client_ident(True), self.nick, ''.join(self.modes.keys())))
            self.broadcast('umode:W',':%s NOTICE *: Client %s connected.' % \
            (self.server.config.server.domain, self.client_ident()))
        else:
            # User isn't quite changing nick
            if self.server.clients.get(nick, None) == self:
                return
            
            else:
                # Nick is available. Change the nick.
                message = ':%s NICK :%s' % (self.client_ident(), nick)

                # Briefly create two references to ourself with the server.
                self.server.clients[nick] = self 
                self.server.clients.pop(self.nick)
                prev_nick = self.nick
                self.nick = nick

                # Carry oper, chanops and channel invites over.
                if self.oper:
                    self.server.opers.pop(prev_nick)
                    self.server.opers[self.nick] = self.oper

                for channel in self.channels.values():
                    if 'v' in channel.modes:
                        if prev_nick in channel.modes['v']:
                            channel.modes['v'].remove(prev_nick)
                            channel.modes['v'].append(self.nick)
                    if 'h' in channel.modes:
                        if prev_nick in channel.modes['h']:
                            channel.modes['h'].remove(prev_nick)
                            channel.modes['h'].append(self.nick)
                    if 'o' in channel.modes:
                        if prev_nick in channel.modes['o']:
                            channel.modes['o'].remove(prev_nick)
                            channel.modes['o'].append(self.nick)
                    if 'a' in channel.modes:
                        if prev_nick in channel.modes['a']:
                            channel.modes['a'].remove(prev_nick)
                            channel.modes['a'].append(self.nick)
                    if 'q' in channel.modes:
                        if prev_nick in channel.modes['q']:
                            channel.modes['q'].remove(prev_nick)
                            channel.modes['q'].append(self.nick)
                    if 'i' in channel.modes:
                        if prev_nick in channel.modes['i']:
                            channel.modes['i'].remove(prev_nick)
                            channel.modes['i'].append(nick)

                # Send a notification of the nick change to all the clients in
                # the channels the client is in.
                for channel in self.channels.values():
                    for client in channel.clients:
                        if client != self: # do not send to client itself.
                            self.broadcast(client.nick,message)
                # Send a notification of the nick change to the client itself
                self.broadcast(self.nick,message)

    @links
    @scripts
    def handle_user(self, params):
        """
        Handle the USER command which identifies the user to the server.
        """
        if params.count(' ') < 3:
            raise IRCError(ERR_NEEDMOREPARAMS, '%s :Not enough parameters' % (USER))

        if not self.user:
            user, mode, unused, realname = params.split(' ', 3)
            self.user = user
            self.realname = realname[1:]
            for mode, script in self.server.scripts.umodes.items():
                self.supported_modes[mode] = script[1]
                script = script[0]
                try:
                    script.execute({'client':self,'mode':mode,'new':True})
                except Exception as err:
                    logging.error('%s in %s' % (err,script.file))
                    self.broadcast('umode:W',':%s ERROR %s found %s in %s while connecting.' % \
                    (self.server.config.server.domain,self.client_ident(), err, script.file))
            return ""

    @links
    @scripts
    def handle_server(self, params):
        """
        Permit a remote server to negotiate linking.
        """
        if self.user or self.nick:
            self.write("Error: This command is reserved for server connections only.")
            self.client.broadcast(
                "umode:W",
                ":%s NOTICE * :Warn: %s has tried the SERVER command. %s is not a remote server." % \
                (self.server.config.server.domain, self.client.client_ident(), self.client.client_ident()))
            return
        
        if not params or len(params.split()) != 4:
            self.client.broadcast(
                "umode:W",
                ":%s NOTICE * :%s tried to negotiate a server link." % \
                (self.server.config.server.domain, self.client.client_ident()))
            self.finish()

        version, domain, net_name, link_key = params.split()

        lmajor, lminor, lrevision = SRV_VERSION.split(".")
        lmajor = re.findall("[0-9]", lmajor)

        rmajor, rminor, rrevision = version.split(".")
        rmajor = re.findall("[0-9]", rmajor)

        if rmajor < lmajor:
            self.client.broadcast(
                "umode:W",
                ":%s NOTICE * :%s tried negotiating a server link from version %s." % \
                (self.server.config.server.domain, self.client.client_ident(), version))
            self.finish()

        if link_key != self.server.link_key:
            self.client.broadcast(
                "umode:W",
                ":%s NOTICE * :%s tried negotiating a server link using an invalid link key." % \
                (self.server.config.server.domain, self.client.client_ident()))
            self.finish()

        return ": ACCEPTED"
   
    @links
    @scripts
    def handle_cap(self, params):
        """
        Acquire the list of IRCv3 capabilities from the server.
        """
        return(":%s UNIMPLEMENTED" % self.server.servername)

    @links
    @scripts
    def handle_lusers(self, params):
        """
        Handle the /lusers command
        """
        self.broadcast(self.nick, ':%s %s %s %i :operator(s) online' % \
            (self.server.servername, RPL_LUSEROP, self.nick, len(self.server.opers)))
        self.broadcast(self.nick, ':%s %s %s %i :channels formed' % \
            (self.server.servername, RPL_LUSERCHANNELS, self.nick, len(self.server.channels)))
        self.broadcast(self.nick, ':%s %s %s :I have %i clients' % \
            (self.server.servername, RPL_LUSERME, self.nick, len(self.server.clients)))

    @links
    @scripts
    def handle_motd(self, params):
        if os.path.exists('MOTD'):
            MOTD = open('MOTD')
            for line in MOTD:
                self.broadcast(self.nick, ":%s 372 %s :- %s" % (self.server.config.server.domain, self.nick, line.strip('\n')))
        else:
            self.broadcast(self.nick, ":%s 372 %s :- MOTD file missing." % (self.server.config.server.domain, self.nick))
        self.broadcast(self.nick, ':%s 376 %s :End of MOTD command.' % (self.server.servername, self.nick))

    @links
    @scripts
    def handle_rules(self, params):
        if os.path.exists('RULES'):
            RULES = open('RULES')
            for line in RULES:
                self.broadcast(self.nick, ":%s 232 %s :- %s" % (self.server.config.server.domain, self.nick, line.strip('\n')))
        else:
            self.broadcast(self.nick, ":%s 434 %s :- RULES file missing." % (self.server.config.server.domain, self.nick))
        self.broadcast(self.nick, ':%s 376 %s :End of RULES command.' % (self.server.servername, self.nick))

    def handle_ping(self, params):
        """
        Handle client PING requests to keep the connection alive.
        """
        self.last_activity = str(time.time())[:10] 
        return(':%s PONG :%s' % (self.server.servername, self.server.servername))

    @links
    @scripts
    def handle_join(self, params):
        """
        Handle the JOINing of a user to a channel. Valid channel names start
        with a # and consist of a-z, A-Z, 0-9 and/or '_'.
        """
        self.last_activity = str(time.time())[:10] 
        new_channel = None 
        channel_names = params.split(' ', 1)[0] # Ignore keys
        for channel_name in channel_names.split(','):
            r_channel_name = channel_name.strip()

            # Valid channel name?
            if not re.match('^#([a-zA-Z0-9_])+$', r_channel_name):
                raise IRCError(ERR_NOSUCHCHANNEL, r_channel_name)

            # Check we're not already there and grab ourselves a channel object
            if r_channel_name not in self.server.channels.keys():
                new_channel = True

            # Check the server isn't full.
            if new_channel and len(self.server.channels) >= MAX_CHANNELS:
                response = ':%s PART :%s' % (self.client_ident(True), r_channel_name)
                self.broadcast(self.nick, response)
                raise IRCError(500, '%s :Cannot join channel (channel limit has been met)' % r_channel_name)

            channel = self.server.channels.setdefault(r_channel_name, IRCChannel(r_channel_name))

            # Check the channel isn't +i
            if 'i' in channel.modes and not self.oper:
                if self.nick in channel.modes['i']:
                    channel.modes['i'].remove(self.nick)
                else:
                    raise IRCError(ERR_INVITEONLYCHAN, ':%s' % channel.name)

            # Check the channel isn't +k
            if 'k' in channel.modes and not self.oper:
                if len(params.split()) < 2 or not params.split()[1] in channel.modes['k']:
                    raise IRCError(ERR_BADCHANNELKEY, '%s :Cannot join channel (+k) - bad key' % channel.name)

            # Check the channel isn't +OA
            if ('O' in channel.modes and not self.oper) or ('A' in channel.modes and not 'A' in self.modes):
                raise IRCError(500, '%s :Must be an IRC operator' % channel.name)

            # Channel bans and exceptions
            if not self.oper:
                if 'b' in channel.modes and 'e' in channel.modes:
                    for b in channel.modes['b']:
                        for e in channel.modes['e']:
                            if re.match(e.split()[0],self.client_ident(True)): break
                        else:
                            if re.match(b.split()[0], self.client_ident(True)):
                                raise IRCError(ERR_BANNEDFROMCHAN, '%s :Cannot join channel (+b)' % channel.name)
                            continue  # executed if the loop ended normally (no break)
                        break  # executed if 'continue' was skipped (break)
                elif 'b' in channel.modes:
                    for b in channel.modes['b']:
                        if re.match(b.split()[0], self.client_ident(True)):
                            raise IRCError(ERR_BANNEDFROMCHAN, '%s :Cannot join channel (+b)' % channel.name)

            # Add scripts to supported modes and set script modes.
            if new_channel:
                channel.modes['o'].append(self.nick)
                for mode, script in self.server.scripts.cmodes.items():
                    channel.supported_modes[mode] = script[1]
                    script = script[0]
                    try:
                        script.execute({'client':self,'channel':channel,'mode':mode,'new':True})
                        if 'cancel' in script.env:
                            if len(channel.clients) < 1:
                                self.server.channels.pop(channel.name)
                            if isinstance(script['cancel'], (str, bytes)):
                                return(script['cancel'])
                            else:
                                return('')
                    except Exception as err:
                        logging.error('%s in %s' % (err,script.file))
                        self.broadcast('umode:W',':%s ERROR %s found %s in %s while joining %s' % \
                        (self.server.config.server.domain,self.client_ident(),err,script.file,r_channel_name))

            # Add ourself to the channel and the channel to users' channel list.
            channel.clients.add(self)
            self.channels[channel.name] = channel

            # Send join message to everybody in the channel, including yourself.
            response = ':%s JOIN :%s' % (self.client_ident(masking=True), r_channel_name)
            if ('I' in self.modes) or ('r' in channel.modes):
                self.broadcast(self.nick,response)
            else:
                self.broadcast(channel.name,response)

            # Send the topic.
            if channel.topic:
                response = ':%s %s %s %s :%s' % \
                    (self.server.config.server.domain, RPL_TOPIC, self.nick, channel.name, channel.topic)
                self.broadcast(self.nick,response)
                response = ':%s %s %s %s %s %s' % \
                    (self.server.config.server.domain, RPL_TOPICWHOTIME, self.nick, channel.name, channel.topic_by, channel.topic_time)
                self.broadcast(self.nick,response)

            self.handle_names(channel.name)

    @scripts
    def handle_names(self, params):
        if params in self.server.channels.keys():
            channel = self.server.channels.get(params)
            if channel:
                if channel.name in self.channels or self.oper:
                    if 'r' in channel.modes and not self.oper:
                        nicks = [channel.supported_modes['r'].split()[0]]
                    else:
                        tmp = []
                        nicks = [client.nick for client in channel.clients]
                        
                        # Find the highest channel op status of each user
                        # without removing any multiple statuses.
                        if 'g' not in channel.modes or self.oper:
                            v = [i for i in channel.modes['v'] if i in nicks]
                            h = [i for i in channel.modes['h'] if i in nicks]
                            o = [i for i in channel.modes['o'] if i in nicks]
                            a = [i for i in channel.modes['a'] if i in nicks]
                            q = [i for i in channel.modes['q'] if i in nicks]
                            for nick in q:
                                if not nick in tmp:
                                    nicks.remove(nick)
                                    tmp.append(nick)
                                    nicks.append('~'+ nick)
                            for nick in a:
                                if not nick in tmp:
                                    nicks.remove(nick)
                                    tmp.append(nick)
                                    nicks.append('&'+ nick)
                            for nick in o:
                                if not nick in tmp:
                                    nicks.remove(nick)
                                    tmp.append(nick)
                                    nicks.append('@'+ nick)
                            for nick in h:
                                if not nick in tmp:
                                    nicks.remove(nick)
                                    tmp.append(nick)
                                    nicks.append('%'+ nick)
                            for nick in v:
                                if not nick in tmp:
                                    nicks.remove(nick)
                                    tmp.append(nick)
                                    nicks.append('+'+ nick)
                self.broadcast(self.nick, ':%s 353 %s = %s :%s' % \
                    (self.server.servername, self.nick, channel.name, ' '.join(nicks)))
                self.broadcast(self.nick, ':%s 366 %s %s :End of /NAMES list' % \
                    (self.server.servername, self.nick, channel.name))
                del tmp, nicks, v, h, o, a, q

    @links
    @scripts
    def handle_mode(self, params):
        """
        Handle the MODE command which sets and requests UMODEs and CMODEs
        """
        # This method parses both +mode params and +mode:param,s for scripts
        # and built-in modes.
        self.last_activity = str(time.time())[:10] 
#       :nick!user@host MODE (#channel) +mode (args)
        if ' ' in params: # User is attempting to set a mode
            modeline = ''
            unknown_modes = ''
            argument = None
            target, mode = params.split(' ', 1)
            if ' ' in mode: mode, argument = mode.split(' ', 1)
            if target.startswith('#'):
                channel = self.server.channels.get(target)
                if not channel:
                    raise IRCError(ERR_NOSUCHCHANNEL, target)
                
                # Retrieving bans and excepts
                if mode in {'b', '+b', 'e', '+e'} and not argument:
                    m = mode[-1] 
                    if m in channel.modes:
                        for item in channel.modes[m]:
                            item = item.split()
                            item[0] = re_to_irc(item[0])
                            item = ' '.join(item)
                            if m =='b': line = ":%s %s %s %s %s" % \
                                (self.server.config.server.domain, RPL_BANLIST, self.nick, channel.name, item)
                            elif m == 'e': line = ":%s %s %s %s %s" % \
                                (self.server.config.server.domain, RPL_EXCEPTLIST, self.nick, channel.name, item)
                            self.broadcast(self.nick,line)
                    
                    if m == 'b': response = ":%s %s %s %s :End of Channel Ban List" % \
                        (self.server.config.server.domain, RPL_ENDOFBANLIST, self.nick, channel.name)
                    
                    elif m == 'e': response = ":%s %s %s %s :End of Channel Exception List" % \
                        (self.server.config.server.domain, RPL_ENDOFEXCEPTLIST, self.nick, channel.name)
                    self.broadcast(self.nick,response)

                elif self.nick in channel.modes['h'] or self.nick in channel.modes['o'] \
                or self.nick in channel.modes['a'] or self.nick in channel.modes['q'] or self.oper:
                    if not argument:
                        args=[]
                        if ':' in mode: mode,args = mode.split(':',1)
                        if args:
                            args = args.split(',')    # /mode +script value value
                        if mode.startswith('+'):      # is the same as /mode +script:value,value
                            mode = mode[1:]
                            if mode in self.server.scripts.cmodes and mode in channel.supported_modes:
                                # Only IRCOPs can set uppercase modes.
                                if mode.isupper() and not self.oper:
                                    return()
                                if not mode in channel.modes:
                                    channel.modes[mode] = args
                                
                                elif type(channel.modes[mode]) == list and args:
                                    channel.modes[mode].extend(args)
                                
                                script = self.server.scripts.cmodes[mode][0]
                                # Send "set=True" into the scripts' namespace so it knows to adjust this channel.
                                try:
                                    
                                    script.execute({'client':       self,
                                                    'channel':      channel,
                                                    'mode':         mode,
                                                    'args':         args,
                                                    'setting_mode': True})

                                    if 'cancel' in script.env:
                                        if isinstance(script['cancel'], (str, bytes)):
                                            return(script['cancel'])
                                        else:
                                            return('')
                                    
                                    self.broadcast(target,":%s MODE %s %s" % \
                                    (self.client_ident(True), target,
                                    params.split()[1]))
                                    return
                                
                                except Exception as err:
                                    del channel.modes[mode]
                                    logging.error('%s in %s' % (err,script.file))
                                    self.broadcast('umode:W',':%s ERROR %s found %s in %s' % \
                                        (self.server.config.server.domain,self.client_ident(), err, script.file))
                            else:
                                for i in mode:
                                    if not i in channel.supported_modes:
                                        unknown_modes = unknown_modes + i
                                        continue
                                    
                                    if i.isupper() and not self.oper:
                                        continue
                                    
                                    if i not in channel.modes:
                                        channel.modes[i] = args
                                        modeline=modeline + i
                            if modeline:
                                message = ":%s MODE %s +%s" % (self.client_ident(True), target, modeline)
                                self.broadcast(target, message)
                            
                            if unknown_modes:
                                self.broadcast(self.nick, ':%s %s %s %s :unkown mode(s)' % \
                                    (self.server.config.server.domain, ERR_UNKNOWNMODE, self.nick, unknown_modes))
                        
                        elif mode.startswith('-'):
                            mode = mode[1:]
                            removed_args=[]
                            
                            if mode in self.server.scripts.cmodes and mode in channel.modes:
                                if mode.isupper() and not self.oper:
                                    return
                                
                                if isinstance(channel.modes[mode], list) and args:
                                    for arg in args:
                                        if arg in channel.modes[mode]:
                                            channel.modes[mode].remove(arg)
                                            removed_args.append(arg)
                                
                                script = self.server.scripts.cmodes[mode][0]
                                try:
                                    script.execute({"client":           self,
                                                    "channel":          channel,
                                                    "mode":             mode,
                                                    "args":             args,
                                                    "setting_mode":     False})
                                    if "cancel" in script.env:
                                        if isinstance(script['cancel'], (str, bytes)):
                                            return(script['cancel'])
                                        else:
                                            return('')
                                except Exception as err:
                                    logging.error('%s in %s' % (err, script.file))
                                    self.broadcast('umode:W',':%s ERROR %s found %s in %s' % \
                                        (self.server.config.server.domain,self.client_ident(),err,script.file))
                                
                                if mode in channel.modes:
                                    # Using "/mode -script:" clears all values.
                                    if isinstance(args, (str, bytes)):
                                        del channel.modes[mode]
                                    
                                    # Here we try to unset the mode if sending "set=False" into the
                                    # script hasn't caused it to extricate its effects from the channel.
                                    elif isinstance(channel.modes[mode], (int, float)):
                                        del channel.modes[mode]
                                    
                                    else:
                                        try:
                                            if len(channel.modes[mode]) == 0:
                                                del channel.modes[mode]
                                        # TODO: Craft a scenario where this
                                        #       pass is met and return output
                                        #       to users about it.
                                        except:
                                            pass
                                if removed_args:
                                    modeline = '%s:%s' % (mode, ','.join(removed_args))
                                else:
                                    modeline = mode
                            else:
                                for i in mode:
                                    if i in channel.modes:
                                        if i.isupper() and not self.oper:
                                            continue
                                        
                                        if i in {'v', 'h', 'o', 'a', 'q', 'e', 'b'}:
                                            continue
                                        
                                        if i == 'i' or (type(channel.modes[i]) == int) or \
                                        (len(channel.modes[i]) == 0):
                                            del channel.modes[i]
                                        modeline = modeline + i
                            if mode in channel.modes:
                                if isinstance(channel.modes[mode], list):
                                    self.write('%s +%s contains \x02%s\x0F.' % \
                                            (channel.name, mode, '\x0F, \x02'.join(channel.modes[mode])))
                                self.write('Use \x02\x1F/MODE %s -%s:\x0F to clear.' % (channel.name,mode))
                            
                            elif modeline:
                                message = ":%s MODE %s -%s" % (self.client_ident(True), target, modeline)
                                self.broadcast(target, message)

                    else: # A mode with arguments. Chan ops, bans, excepts..
                        args=argument.split(' ')
                        if mode.startswith('+'):
                            mode = mode[1:]
                            if mode in self.server.scripts.cmodes and mode in channel.supported_modes:
                                if mode.isupper() and not self.oper:
                                    return
                                if not mode in channel.modes:
                                    channel.modes[mode] = args
                                elif isinstance(channel.modes[mode], list) and args:
                                    channel.modes[mode].extend(args)
                                
                                script = self.server.scripts.cmodes[mode][0]
                                try:
                                    script.execute({'client':       self,
                                                    'channel':      channel,
                                                    'mode':         mode,
                                                    'args':         args,
                                                    'setting_mode': True})
                                    if 'cancel' in script.env:
                                        if isinstance(script['cancel'], (str, bytes)):
                                            return(script['cancel'])
                                        else:
                                            return
                                    modeline = mode
                                except Exception as err:
                                    del channel.modes[mode]
                                    logging.error('%s in %s' % (err, script.file))
                                    self.broadcast('umode:W',':%s ERROR %s found %s in %s' % \
                                    (self.server.config.server.domain,self.client_ident(), err, script.file))
                            else:
                                for i in mode:
                                    if not i in channel.supported_modes:
                                        unknown_modes += i
                                        continue
                                    
                                    for n in args:
                                        if (i == 'v' or i == 'h' or i == 'o' or \
                                        i == 'a' or i == 'q') and (i in channel.supported_modes):
                                            if not i in channel.modes: channel.modes[i]=[]
                                            if not self.oper:
                                                if (i == 'a' or i == 'q') and \
                                                (not self.nick in channel.modes['q']):
                                                    raise IRCError(ERR_CHANOWNPRIVNEEDED,
                                                    "%s You're not a channel owner." % \
                                                    channel.name)
                                                
                                                if (i == 'o') and (not self.nick \
                                                in channel.modes['o'] and not \
                                                self.nick in channel.modes['a'] \
                                                and not self.nick in channel.modes['q']):
                                                    raise IRCError(ERR_NOTFORHALFOPS,
                                                    "Halfops cannot set mode %s" % i)
                                            
                                            if n not in channel.modes[i]:
                                                channel.modes[i].append(n)
                                                modeline += i
                                                args.remove(n)
                                        
                                        elif (i == 'b' or i == 'e') and i in channel.supported_modes:
                                            n = re_to_irc(n,False)
                                            if not i in channel.modes: channel.modes[i]=[]
                                            channel.modes[i].append('%s %s %s' % \
                                            (n, self.nick, str(time.time())[:10]))
                                            modeline+=i
                            
                            if modeline:
                                message = ":%s MODE %s +%s %s" % \
                                (self.client_ident(True), target, modeline,
                                argument)
                                self.broadcast(target,message)
                            
                            if unknown_modes:
                                self.broadcast(self.nick,
                                ':%s %s %s %s :unkown mode(s)' % \
                                (self.server.config.server.domain, ERR_UNKNOWNMODE, self.nick, unknown_modes))
                        
                            elif mode.startswith('-'):
                                mode = mode[1:]
                                removed_args=[]
                            
                            if mode in self.server.scripts.cmodes and mode in channel.modes:
                                if mode.isupper() and not self.oper:
                                    return

                                if isinstance(channel.modes[mode], list) and args:
                                    for arg in args:
                                        if arg in channel.modes[mode]:
                                            channel.modes[mode].remove(arg)
                                            removed_args.append(arg)
                                
                                script = self.server.scripts.cmodes[mode][0]
                                try:
                                    script.execute({'client':       self,
                                                    'channel':      channel,
                                                    'mode':         mode,
                                                    'args':         args,
                                                    'setting_mode': False})
                                    if 'cancel' in script.env:
                                        if isinstance(script['cancel'], (str, bytes)):
                                            return(script['cancel'])
                                        else:
                                            return('')
                                except Exception as err:
                                    logging.error('%s in %s' % (err, script.file))
                                    self.broadcast('umode:W',':%s ERROR %s found %s in %s' % \
                                    (self.server.config.server.domain,self.client_ident(), err, script.file))
                                if mode in channel.modes:
                                    if isinstance(channel.modes[mode], (int, float)):
                                        del channel.modes[mode]
                                    else:
                                        try:
                                            if len(channel.modes[mode]) == 0:
                                                del channel.modes[mode]
                                        except:
                                            pass
                                modeline = mode
                            else:
                                for i in mode:
                                    for n in args:
                                        if i not in channel.modes:
                                            unknown_modes += n
                                            continue
                                        
                                        if (i == 'v' or i == 'h' or i == 'o' or \
                                        i == 'a' or i == 'q') and (i in channel.modes):
                                            if not self.oper:
                                                if (i == 'a' or i == 'q') and \
                                                (not self.nick in channel.modes['q']):
                                                    raise IRCError(ERR_CHANOWNPRIVNEEDED,
                                                    "%s You're not a channel owner." % channel.name)
                                                
                                                if (i == 'o') and (not self.nick \
                                                in channel.modes['o'] and not \
                                                self.nick in channel.modes['a'] \
                                                and not self.nick in channel.modes['q']):
                                                    raise IRCError(ERR_NOTFORHALFOPS,
                                                    "Halfops cannot unset mode %s" % i)
                                            
                                            if n in channel.modes[i]:
                                                channel.modes[i].remove(n)
                                                modeline += i
                                                args.remove(n)
                                        
                                        elif (i == 'b' or i == 'e') and i in channel.modes:                  
                                            n = re_to_irc(n, False)
                                            for entry in channel.modes[i]:
                                                if entry.split()[0] == n:
                                                    channel.modes[i].remove(entry)
                                                    modeline+=i
                                        
                                        elif i == 'i':
                                            del channel.modes[i]
                                            modeline += i
                            if modeline:
                                message = ":%s MODE %s -%s %s" % \
                                (self.client_ident(True), target,
                                modeline, argument)
                                self.broadcast(target, message)                
                else:
                    raise IRCError(ERR_CHANOPPRIVSNEEDED,
                    '%s You are not a channel operator.' % channel.name)

            else: # User modes.
                if (self.nick == target) or self.oper:
                    user = self.server.clients.get(target)
                    if not user: raise IRCError(ERR_NOSUCHNICK, target)
                    modeline = ''
                    if mode.startswith('+'):
                        for i in mode[1:]:
                            if i in self.supported_modes and i not in self.modes:
                                if i.isupper() and not self.oper:
                                    continue
                                user.modes[i] = 1
                                modeline = modeline + i
                        
                        if len(modeline) > 0:
                            response = ':%s MODE %s +%s' % \
                            (self.client_ident(True), user.nick, modeline)
                            self.broadcast(self.nick,response)
                            if user.nick != self.nick:
                                self.broadcast(user.nick, response)
                    
                    elif mode.startswith('-'):
                        for i in mode[1:]:
                            if i in user.modes:
                                if i.isupper() and not self.oper:
                                    continue
                                del user.modes[i]
                                modeline = modeline + i
                        
                        if len(modeline) > 0:
                            response = ':%s MODE %s -%s' % \
                            (self.client_ident(True), user.nick, modeline)
                            self.broadcast(self.nick,response)
                            if user.nick != self.nick:
                                self.broadcast(user.nick, response)

        else: # User is requesting a list of modes
            if params.startswith('#'):
                modes=''
                scripts=[] 
                channel = self.server.channels.get(params)
                if not channel:
                    raise IRCError(ERR_NOSUCHCHANNEL, '%s :%s' % (params, params))
                
                if not self.oper and self not in channel.clients:
                    raise IRCError(ERR_NOTONCHANNEL,
                    '%s :%s You are not in that channel.' % \
                    (channel.name, channel.name))
                
                for mode in channel.modes:
                    if mode in {'v', 'h', 'o', 'a', 'q', 'e', 'b'}:
                        continue
                    if mode in self.server.scripts.cmodes:
                        ns = {'client': self, 'channel': channel, 'mode': mode,
                              'display': True}
                        script = self.server.scripts.cmodes[mode][0]
                        try:
                            # Using "item" to avoid race conditions.
                            item = script.execute(ns)
                            if 'output' in item:
                                scripts.append('%s %s' % (mode, item['output']))
                            else:
                                scripts.append(mode)
                        except Exceptiona as err:
                            logging.error('%s in %s' % (err, script.file))
                            self.broadcast('umode:W',':%s ERROR %s found %s in %s' % \
                                (self.server.config.server.domain, self.client_ident(), err, script.file))
                    if len(mode) == 1:
                        modes = modes + mode
                self.broadcast(self.nick,':%s 324 %s %s +%s' % \
                (self.server.servername, self.nick, params, modes))
                for item in scripts:
                    self.broadcast(self.nick,':%s 324 %s %s +%s' % \
                    (self.server.config.server.domain, self.nick, params, item))
            
            elif self.oper or params == self.nick:
                modes = '+'
                scripts = []
                user = self.server.clients.get(params)
                if not user:
                    raise IRCError(ERR_NOSUCHNICK, params)
                
                for mode in user.modes:
                    if mode in self.server.scripts.umodes:
                        ns = {'client': self, 'mode': mode, 'display': True}
                        script = self.server.scripts.umodes[mode][0]
                        try:
                            item = script.execute(ns)
                            if 'output' in item:
                                scripts.apppend('%s %s' % (mode, item['output']))
                            else:
                                scripts.append(mode)
                            scripts.append(item)
                        except Exception as err:
                            logging.error('%s in %s' % (err, script.file))
                            self.broadcast('umode:W',':%s ERROR %s found %s in %s' % \
                                (self.server.config.server.domain,self.client_ident(), err, script.file))
                    if len(mode) == 1:
                        modes = modes + mode
                self.broadcast(self.nick,':%s %s %s :%s' % \
                (self.server.config.server.domain, RPL_UMODEIS, params, modes))
                for item in scripts: self.broadcast(self.nick,':%s %s %s %s +%s' % \
                    (self.server.config.server.domain, RPL_UMODEIS, params, item))

    @links
    @scripts
    def handle_invite(self, params):
        """
        Handle the invite command.
        """
        self.last_activity = str(time.time())[:10] 
        target, channel = params.strip(':').split(' ',1)
        channel = self.server.channels.get(channel)
        if channel and 'i' in channel.modes and target in self.server.clients:
            if self.nick in channel.modes['h'] or self.nick in channel.modes['o'] \
            or self.nick in channel.modes['a'] or self.nick in channel.modes['q'] or self.oper:
                channel.modes['i'].append(target)

                response = ':%s %s %s %s %s' % \
                    (self.server.config.server.domain, RPL_INVITING, self.nick, target, channel.name)
                self.broadcast(self.nick, response)

                # Tell the channel
                response = ':%s NOTICE @%s :%s invited %s into the channel.' % \
                    (self.server.config.server.domain, channel.name, self.nick, target)
                self.broadcast(channel.name, response)

                # Tell the invitee
                response = ':%s INVITE %s :%s' % \
                    (self.client_ident(True), target, channel.name)
                self.broadcast(target, response)
            else:
                raise IRCError(ERR_CHANOPPRIVSNEEDED, '%s :%s You are not a channel operator.' % \
                    (channel.name, channel.name))

    @links
    @scripts
    def handle_knock(self, params):
        self.last_activity = str(time.time())[:10] 
        channel = self.server.channels.get(params)
        if channel:
            if 'i' in channel.modes and not channel.name in self.channels:
                response = ':%s NOTICE @%s :%s knocked on %s.' % \
                    (self.server.config.server.domain, channel.name, self.nick, channel.name)
                self.broadcast(channel.name, response)
                response = ':%s NOTICE %s : Knocked on %s' % \
                    (self.server.config.server.domain, self.nick, channel.name)
                self.broadcast(self.nick, response)

    @links
    @scripts
    def handle_whois(self, params):
        """
        Handle the whois command.
        """
        self.last_activity = str(time.time())[:10] 
        # TODO: IP Addr, Admin, Oper, Bot lines.
        user = self.server.clients.get(params)
        if not user:
            raise IRCError(ERR_UNKNOWNCOMMAND, '%s is a cool guy.' % \
                params.split(' ', 1)[0])
        
        # Userhost line.
        if user.vhost:
            response = ':%s %s %s %s %s %s * %s' % \
                (self.server.config.server.domain, RPL_WHOISUSER, self.nick, user.nick,
                user.nick, user.vhost, user.realname)
            self.broadcast(self.nick,response)
        else:
            response = ':%s %s %s %s %s %s * %s' % \
                (self.server.config.server.domain, RPL_WHOISUSER, self.nick, user.nick,
                user.nick, user.hostmask, user.realname)
            self.broadcast(self.nick,response)

        # Channels the user is in. Modify to show op status.
        channels = []
        for channel in user.channels.values():
            if 'p' not in channel.modes:
                channels.append(channel.name)
        if channels:
            response = ':%s %s %s %s :%s' % \
                (self.server.config.server.domain, RPL_WHOISCHANNELS, self.nick, user.nick,
                ' '.join(channels))
            self.broadcast(self.nick, response)

        # Oper info
        if user.oper and 'H' not in user.modes:
            if 'A' in user.modes:
                response = ':%s %s %s %s :%s is a server admin.' % \
                    (self.server.config.server.domain, RPL_WHOISOPERATOR, self.nick, user.nick,
                        user.nick)
                self.broadcast(self.nick, response)
            if 'O' in user.modes:
                response = ':%s %s %s %s :%s is a server operator.' % \
                    (self.server.config.server.domain, RPL_WHOISOPERATOR, self.nick, user.nick,
                        user.nick)
                self.broadcast(self.nick, response)

        if self.oper or self.nick == user.nick:
            if user.rhost:
                response = ':%s %s %s %s %s %s' % \
                    (self.server.config.server.domain, RPL_WHOISSPECIAL, self.nick, user.nick,
                    user.rhost, user.host[0])
                self.broadcast(self.nick, response)
            else:
                response = ':%s %s %s %s %s' % \
                    (self.server.config.server.domain, RPL_WHOISSPECIAL, self.nick, user.nick,
                        user.host[0])
                self.broadcast(self.nick, response)

        # Script / Plugin user modes
        for mode in user.modes:
            if hasattr(user.modes[mode], "__whois__"):
                try:
                    
                    for line in user.modes[mode].__whois__.splitlines():
                        response = ':%s %s %s %s +%s: %s' % \
                            (self.server.config.server.domain, RPL_WHOISSPECIAL, self.nick, user.nick,
                            mode, line)
                        self.broadcast(self.nick, response)
                except Exception as err:
                    logging.error("Error parsing __whois__ attribute for user mode \"%s\"." % mode)
                    logging.error(str(err))

        # Server info line
        response = ':%s %s %s %s %s :%s' % \
            (self.server.config.server.domain, RPL_WHOISSERVER, self.nick, user.nick,
                self.server.config.server.domain, SRV_DESCRIPTION)
        self.broadcast(self.nick, response)

        if 'Z' in user.modes:
            response = ':%s %s %s %s :is using a secure connnection' % \
                (self.server.config.server.domain, RPL_WHOISSECURE, self.nick, user.nick)
            self.broadcast(self.nick, response)

        # Idle and connection time.
        idle_time = int(str(time.time())[:10]) - int(user.last_activity)
        response = ':%s %s %s %s %i %s :seconds idle, signon time' % \
            (self.server.config.server.domain, RPL_WHOISIDLE, self.nick, user.nick, idle_time,
                user.connected_at)
        self.broadcast(self.nick, response)

        # That about wraps 'er up.
        response = ':%s %s %s %s :End of /WHOIS list.' % (self.server.config.server.domain,
            RPL_ENDOFWHOIS, self.nick, user.nick)

    @links
    @scripts
    def handle_who(self, params):
        """
        Handle the who command.
        Currently doesn't handle modes we don't natively support.
        """
        if params.startswith('#'):
            channel = self.server.channels.get(params)
            if not channel: raise IRCError(ERR_NOSUCHNICK, params)
            else:
                for client in channel.clients:
                    host = client.client_ident(True)
                    host = host.split('@')[1]
                    if client.oper:
                        self.broadcast(self.nick, ":%s %s %s %s %s %s %s %s H* :n/a %s" % \
                        (self.server.config.server.domain, RPL_WHOREPLY, self.nick, channel.name,
                        client.user, host, self.server.config.server.domain, client.nick,
                        client.realname))
                    else:
                        self.broadcast(self.nick, ":%s %s %s %s %s %s %s %s H :n/a %s" % \
                        (self.server.config.server.domain, RPL_WHOREPLY, self.nick, channel.name,
                        client.user, host, self.server.config.server.domain, client.nick,
                        client.realname))
                self.broadcast(self.nick, ":%s %s %s %s :End of /WHO list." % \
                (self.server.config.server.domain, RPL_ENDOFWHO, self.nick, channel.name))            
        
        elif self.oper and params == '*':
            for client in self.server.clients.values():
                host = client.client_ident(True)
                host = host.split('@')[1]
                if client.oper:
                    self.broadcast(self.nick, ":%s %s %s - %s %s %s %s H* :n/a %s" % \
                    (self.server.config.server.domain, RPL_WHOREPLY, self.nick, client.user, host,
                    self.server.config.server.domain, client.nick, client.realname))
                else:
                    self.broadcast(self.nick, ":%s %s %s %s %s %s %s H :n/a %s" % \
                    (self.server.config.server.domain, RPL_WHOREPLY, self.nick, client.user, host,
                    self.server.config.server.domain, client.nick, client.realname))
            self.broadcast(self.nick, ":%s %s %s %s :End of /WHO list." % \
            (self.server.config.server.domain, RPL_ENDOFWHO, self.nick, client.nick))
        
        else:
            client = self.server.clients.get(params)
            if not client: raise IRCError(ERR_NOSUCHNICK, params)
            else:
                host = client.client_ident(True)
                host = host.split('@')[1]
                if client.oper:
                    self.broadcast(self.nick, ":%s %s %s - %s %s %s %s H* :n/a %s" % \
                    (self.server.config.server.domain, RPL_WHOREPLY, self.nick, client.user, host,
                    self.server.config.server.domain, client.nick, client.realname))
                else:
                    self.broadcast(self.nick, ":%s %s %s %s %s %s %s H :n/a %s" % \
                    (self.server.config.server.domain, RPL_WHOREPLY, self.nick, client.user, host,
                    self.server.config.server.domain, client.nick, client.realname))
                self.broadcast(self.nick, ":%s %s %s %s :End of /WHO list." % \
                (self.server.config.server.domain, RPL_ENDOFWHO, self.nick, client.nick))

    @scripts
    def handle_topic(self, params):
        """
        Handle a topic command.
        """
        self.last_activity = str(time.time())[:10] 
        if ' ' in params:
            channel_name = params.split(' ', 1)[0]
            topic = params.split(' ', 1)[1].lstrip(':')
        else:
            channel_name = params
            topic = None
        
        channel = self.server.channels.get(channel_name)
        if not channel:
            raise IRCError(ERR_NOSUCHCHANNEL, 'PRIVMSG :%s' % (channel_name))
        
        if not channel.name in self.channels:
            # The user isn't in the channel.
            raise IRCError(ERR_CANNOTSENDTOCHAN, '%s :Cannot send to channel' % (channel.name))
        
        if topic:
            if self.nick in channel.modes['h'] or self.nick in channel.modes['o'] \
            or self.nick in channel.modes['a'] or self.nick in channel.modes['q'] or self.oper:
                if topic == channel.topic:
                    return
                channel.topic = topic
                channel.topic_by = self.nick
                channel.topic_time = str(time.time())[:10]
                message = ':%s TOPIC %s :%s' % (self.client_ident(), channel_name, channel.topic)
                self.broadcast(channel.name,message)
            
            else:
                raise IRCError(ERR_CHANOPPRIVSNEEDED, '%s :%s You are not a channel operator.' % \
                    (channel.name,channel.name))
        
        else:
            self.broadcast(self.nick, ':%s %s %s %s :%s' % \
                (self.server.config.server.domain, RPL_TOPIC, self.nick, channel.name, channel.topic))
            self.broadcast(self.nick, ':%s %s %s %s %s %s' % \
                (self.server.config.server.domain, RPL_TOPICWHOTIME, self.nick, channel.name,
                channel.topic_by, channel.topic_time))

    @scripts
    def handle_part(self, params):
        """
        Handle a client parting from channel(s).
        """
        self.last_activity = str(time.time())[:10] 
        for pchannel in params.split(','):
            if pchannel.strip() in self.channels:
                # Send message to all clients in all channels user is in, and
                # remove the user from the channels.
                channel = self.server.channels.get(pchannel.strip())
                if ('r' not in channel.modes) or (len(channel.clients) == 1):
                    response = ':%s PART :%s' % (self.client_ident(True), pchannel)
                    self.broadcast(channel.name,response)
                self.channels.pop(pchannel)
                channel.clients.remove(self)
                if len(channel.clients) < 1:
                    self.server.channels.pop(channel.name)
            else:
                response = ':%s 403 %s :%s' % \
                (self.server.servername, pchannel, pchannel)
                self.broadcast(self.nick,response)

    @scripts
    def handle_quit(self, params):
        """
        Handle the client breaking off the connection with a QUIT command.
        """
        response = ':%s QUIT :%s' % (self.client_ident(True), params.lstrip(':'))
        self.finish(response)

    @scripts
    def handle_kick(self, params):
        """
        Implement the kick command
        """
        self.last_activity = str(time.time())[:10] 
        message = None
        channel, target = params.split(' ',1)
        if ':' in target:
            target, message = target.split(' :',1)

        channel = self.server.channels.get(channel)
        if not channel:
            return(':%s NOTICE %s :No such channel.' % (self.server.config.server.domain, self.nick))

        if not self.oper and self.nick not in channel.modes['h'] and self.nick \
            not in channel.modes['o'] \
        and self.nick not in channel.modes['a'] and self.nick not in \
        channel.modes['q']:
            return(':%s %s %s %s :You are not a channel operator.' % \
            (self.server.config.server.domain, ERR_CHANOPPRIVSNEEDED, self.nick, channel.name))

        target = self.server.clients.get(target)
        if not target:
            raise IRCError(ERR_NOSUCHNICK, target)

            return(':%s NOTICE @%s :No such nick.' % (self.server.config.server.domain, channel.name))
        if 'Q' in target.modes:
            return(':%s NOTICE @%s :Cannot kick +Q user %s.' % (self.server.config.server.domain,
                channel.name, target.nick))

        if not self.oper:
            if not self.nick in channel.modes['q'] and target.nick in channel.modes['q']:
                return(":%s %s %s %s :Can't kick %s." % \
                        (self.server.config.server.domain, ERR_CHANOPPRIVSNEEDED, self.nick,
                        channel.name, target.nick))
            if (not self.nick in channel.modes['a'] and not self.nick in \
                channel.modes['q']) and (target.nick in channel.modes['a'] \
            or target.nick in channel.modes['q']):
                return(":%s %s %s %s :Can't kick %s." % \
                    (self.server.config.server.domain, ERR_CHANOPPRIVSNEEDED, self.nick,
                    channel.name, target.nick))
            if (not self.nick in channel.modes['o'] and not self.nick in \
                channel.modes['a'] and not self.nick in channel.modes['q']) \
            and (target.nick in channel.modes['o'] or target.nick in \
            channel.modes['a'] or target.nick in channel.modes['q']):
                return(":%s %s %s %s :Can't kick %s." % \
                    (self.server.config.server.domain, ERR_CHANOPPRIVSNEEDED, self.nick, channel.name, \
                    target.nick))

        if message:
            response = ':%s KICK %s %s :%s' % \
            (self.client_ident(True), channel.name, target.nick, message)
        else:
            response = ':%s KICK %s %s :%s' % \
                (self.client_ident(True), channel.name, target.nick, self.nick)

        for op_list in channel.ops:
            if target.nick in op_list:
                op_list.remove(target.nick)
        
        self.broadcast(channel.name, response)
        target.channels.pop(channel.name)
        channel.clients.remove(target)

    @scripts
    def handle_list(self, params):
        """
        Implements the /list command
        """
        self.last_activity = str(time.time())[:10] 
        self.broadcast(self.nick, ':%s %s %s Channel :Users  Name' % \
            (self.server.config.server.domain, RPL_LISTSTART, self.nick))
        for channel in self.server.channels.values():
            if ('s' not in channel.modes) or ('S' in self.modes):
                tmp_modes = []
                for mode in channel.modes:
                    if mode not in ['v', 'h', 'o', 'a', 'q', 'e', 'b']:
                        tmp_modes.append(mode)
                self.broadcast(self.nick, ':%s %s %s %s %i :[+%s] %s' % \
                (self.server.config.server.domain,RPL_LIST, self.nick, channel.name, len(channel.clients),
                ''.join(tmp_modes), channel.topic))
        return(':%s %s %s :End of /LIST' % (self.server.config.server.domain, RPL_LISTEND, self.nick))

    @scripts
    def handle_oper(self, params):
        """
        Handle the client authenticating itself as an ircop.
        """
        if OPER_PASSWORD == False:
            raise IRCError(ERR_UNKNOWNCOMMAND, ': OPER system is disabled.')
        else:
            if ' ' in params:
                modeline = ''
                opername, password = params.split(' ', 1)
                password = hashlib.sha512(password.encode('utf-8')).hexdigest()
                
                if password == OPER_PASSWORD and opername == OPER_USERNAME:
                    oper = self.server.opers.setdefault(self.nick, IRCOperator(self))
                    self.modes['A'], self.modes["N"] = 1, 1
                    modeline += 'AN'
                else:
                    oper = self.server.opers.get(opername)
                    if (not oper) or (not oper.passwd) or (oper.passwd != password):
                        return ':%s NOTICE %s :No O:Lines for your host.' % \
                                (self.server.config.server.domain, self.nick)
                
                self.vhost = oper.vhost
                self.oper = oper
                self.broadcast('umode:W', ':%s NOTICE _ :%s is now an IRC operator.' % \
                    (self.server.config.server.domain, self.nick))
                for i in oper.modes:
                    self.modes[i] = 1
                    modeline = modeline + i
                self.broadcast(self.nick, ':%s MODE %s +%s' %
                               (self.server.config.server.domain, self.nick, modeline))
                return(':%s NOTICE %s :Auth successful for %s.' %
                        (self.server.config.server.domain, self.nick, opername))
            else:
                return(': Incorrect usage.')

    @scripts
    def handle_operserv(self, params):
        """
        Pass authenticated ircop commands to the IRCOperator dispatcher.
        """
        if self.oper:
            return(self.oper.dispatch(params))
        else:
            return(': OPERSERV is only available to authenticated IRCops.')

    @scripts
    def handle_chghost(self, params):
        if self.oper:
            target, vhost = params.split(' ',1)
            target = self.server.clients.get(target)
            if target:
                target.vhost = vhost
                return(':%s NOTICE %s :Changed the vhost for %s to %s.' % \
                    (self.server.config.server.domain, self.nick, target.nick, target.vhost))
            else:
                return(':%s NOTICE %s :Invalid nick: %s.' % (self.server.config.server.domain, self.nick, target))
        else:
            return(':%s NOTICE %s :You must be identified as an operator to use CHGHOST.' % \
                (self.server.config.server.domain, self.nick))

    @scripts
    def handle_kill(self, params):
        nick, reason = params.split(' ', 1)
        reason = reason.lstrip(':')
        if self.oper:
            client = self.server.clients.get(nick)
            if client:
                if 'A' in client.modes:
                    return(':%s ERROR %s is an IRC Administrator.' % \
                        (self.server.config.server.domain, client.nick))
                else:
                    client.finish(':%s QUIT :Killed by %s: %s' % \
                        (client.client_ident(True), self.nick, reason))

    @scripts
    def handle_helpop(self, params):
        """
        The helpop system provides help on commands and modes.
        Use "/helpop command commandname" for documentation on a given command.
        Use "/helpop cmode modename" for documentation on a given channel mode.
        Use "/helpop umode modename" for documentation on a given user mode.
        """
        if params == "command":
            response = ": Available commands are %s." % \
                ', '.join([c[7:] for _ in dir(self) if _.startswith("handle_")])
            self.broadcast(self.nick, response)

        elif params == "umode": pass
        elif params == "cmode": pass
        elif params == "ocommand" and self.oper:
            response = ": Available OperServ commands are %s." % \
                ', '.join([c[7:] for _ in dir(self.oper) if _.startswith("handle_")])
            self.broadcast(self.nick, response)
        
        elif not ' ' in params:
            docs = self.handle_helpop.__doc__.split('\n')
            doc = ''
            for line in docs:
                i = 0
                for character in line:
                    if character == ' ': i += 1
                    else:
                        doc += line[i:] + '\n'
                        break
            message = ": %s" % doc
            self.broadcast(self.nick, message)
            if self.oper:
                message = ': Use "/helpop ocommand commandname" for documentation on a given operserv command.'
                self.broadcast(self.nick, message)
        
        else:
            (section, topic) = params.split(' ', 1)
            if section == "umode":
                if topic in self.supported_modes:
                    message = ": %s help on user mode %s" % (self.server.config.server.domain, topic)
                    self.broadcast(self.nick, message)
                    message = ": %s" % self.supported_modes[topic]
                    self.broadcast(self.nick, message)
            
            elif section == "command":   
                if hasattr(self, "handle_" + topic):   
                    message = ": %s help on command %s" % (self.server.config.server.domain,
                                                           topic.upper())
                    self.broadcast(self.nick, message)
                    command = getattr(self, "handle_" + topic)
                    docs = command.__doc__.split('\n') 
                    doc = ''
                    for line in docs:
                        i = 0
                        for character in line:
                            if character == ' ': i += 1
                            else:
                                doc += line[i:] + '\n'
                                break
                    message = ": %s" % doc
                    self.broadcast(self.nick, message)
                else:
                    message = ": Unknown command %s" % topic.upper()
                    self.broadcast(self.nick, message)
            
            elif section == "ocommand":
                if self.oper:
                    if hasattr(self.oper, "handle_" + topic):
                        message = ": %s help on operserv command %s" % (
                            self.server.config.server.domain, topic.upper())
                        self.broadcast(self.nick, message)
                        command = getattr(self.oper, "handle_" + topic)
                        docs = command.__doc__.split('\n')
                        doc = ''  
                        for line in docs:
                            i = 0
                            for character in line:
                                if character == ' ':
                                    i += 1
                                else:
                                    doc += line[i:] + '\n'
                                    break
                        message = ": %s" % doc
                        self.broadcast(self.nick, message)
                    else:
                        message = ": Unknown operserv command %s" % topic.upper()
                        self.broadcast(self.nick, message)
                else:
                    message = ": You must be an IRC Operator to view the ocommand section."
                    self.broadcast(self.nick, message)

    @scripts
    def handle_kline(self, params):
        """
        Syntax: /kline add host reason
                /kline remove host
                /kline list

        Permits IRC Operators to ban a given address from the server.
        Addresses may contain wildcards. A reason must also be supplied.
        Hosts that match newly defined K:Lines will be disconnected.
        """
        if self.oper:
            if not params or params.lower() == 'list':

                if not self.server.lines['K']:
                    return(': There are no K:Lines defined on this server.')

                data = []
                for kline, attributes in self.server.lines['K'].items():
                    t = int(attributes[1])
                    tmp={}
                    tmp['Operator'] = attributes[0]
                    tmp['Host'] = re_to_irc(kline)
                    tmp['Time'] = '%s (%s)' % (time.ctime(t), tconv(time.time() - t) + ' ago')
                    tmp['Reason'] = attributes[2]
                    data.append(tmp)
                fmt = format(data)
                self.write(tabulate(fmt, ul='-')(data))
                del data, fmt, table, t, tmp
                return

            cmd = params.split()[0]
            if cmd.lower() == 'add':
                if len(params.split()) < 3:
                    raise IRCError(ERR_NEEDMOREPARAMS, "You must also supply a reason.")
                t = str(time.time())[:10]
                host, reason = params.split(' ',2)[1:]
                host = re_to_irc(host,False)
                if host in self.server.lines['K']: raise IRCError(500, "Host already K:Lined.")
                self.server.lines['K'][host] = [self.client_ident(True), t, reason]
                self.broadcast('umode:W', ':%s NOTICE * :%s added a K:Line for %s "%s"' % \
                    (self.server.config.server.domain, self.client_ident(True), re_to_irc(host), reason))
                
                for client in self.server.clients.values():
                    if 'A' in client.modes or 'O' in client.modes:
                        self.broadcast(self.nick,
                                ":%s NOTICE * :The K:Line for %s matches your host!" % \
                                (self.server.config.server.domain, re_to_irc(host)))
                        continue
                    if re.match(host, client.host[0]):
                        self.broadcast('umode:W', ":%s NOTICE * :%s matches this K:Line." %\
                            (self.server.config.server.domain, client.client_ident()))
                        client.request.send(': This host is K:Lined. Reason: %s\n' % reason)
                        client.handle_quit("K:Lined. Reason: %s" % reason)
                        client.request.close()

            elif cmd.lower() == 'remove':
                if not ' ' in params:
                    raise IRCError(ERR_NEDMOREPARAMS, "You didn't specify which K:Line to remove.")
                host = re_to_irc(params.split()[1], False)
                if host in self.server.lines['K']:
                    del self.server.lines['K'][host]
                self.broadcast('umode:W', ':%s NOTICE * :%s removed the K:Line for %s' % \
                    (self.server.config.server.domain, self.client_ident(True), params.split()[1]))

    def client_ident(self, masking=None):
        """
        Return the client identifier as included in many command replies.
        """
        if masking:
            if self.vhost == None:
                return('%s!%s@%s' % (self.nick, self.user, self.hostmask))
            else:
                return('%s!%s@%s' % (self.nick, self.user, self.vhost))
        else:
            return('%s!%s@%s' % (self.nick, self.user, self.host[0]))

    @scripts
    def finish(self, response=None):
        """
        The client conection is finished. Do some cleanup to ensure that the
        client doesn't linger around in any channel or the client list, in case
        the client didn't properly close the connection with PART and QUIT.
        """
        if not self.nick:
            return
        
        if not response:
            response = ':%s QUIT :Connection reset by peer' % (self.client_ident(True))
        
        if not self.nick in self.server.clients:
            return

        for mode in self.modes:
            if hasattr(self.modes[mode], "__exit__"):
                self.modes[mode].__exit__()

#        self.request.send(response)
        peers = []
        for channel in self.channels.values():
            if self in channel.clients:
                # Remove this nick from any ops lists
                # and then remove the nick from the channel's list of clients.
                # That way we can collect the remaining users to transmit the
                # disconnect message to.
                for op_list in channel.ops:
                    if self.nick in op_list:
                        op_list.remove(self.nick)
                channel.clients.remove(self)
            if len(channel.clients) < 1 and channel.name in self.server.channels:
                self.server.channels.pop(channel.name)
            else:
                for p in channel.clients: peers.append(p)

        # `IRCClient.broadcast` garbage collects stoned clients by invoking
        # this method. We don't write to ourselves via `IRCClient.broadcast`
        # here because we hit max recursion depth for having already invoked
        # `self.request.close`.
        if self in peers:
            self.request.send(response)
            peers.remove(self)
        
        peers = set(peers)
        for peer in peers:
            self.broadcast(peer.nick, response)
        
        try:
            self.server.clients.pop(self.nick)
        except KeyError:
            return
        
        self.broadcast('umode:W', ':%s NOTICE *: Client %s disconnected.' % \
            (self.server.config.server.domain, self.client_ident()))
        logging.info('Client disconnected: %s' % (self.client_ident()))
        
        if len(self.server.clients) == 0:
            logging.info('There goes the last client.')
        
        self.request.close()

    def __repr__(self):
        """
        Return a user-readable description of the client
        """
        return('<%s %s!%s@%s (%s) at %s>' % (
            self.__class__.__name__,
            self.nick,
            self.user,
            self.host[0],
            self.realname,
            hex(id(self))
            )
        )

class IRCServer(object):
    def __init__(self, EventLoop, config, server_address, plugin_paths=[], read_on_exec=False):
        self.sock           = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.servername     = SRV_DOMAIN
        self.loop           = EventLoop
        self.loop.server    = self
        self.config         = config        # Many handler methods in `IRCClient` rely on config values.
        self.channels       = {}            # Existing channels (IRCChannel instances) by channel name.
        self.clients        = {}            # Connected clients (IRCClient instances) by nickname.
        self.opers          = {}            # Authenticated IRCops (IRCOperator instances) by nickname.
        self.scripts        = Scripts(self) # The scripts object we attach external execution routines to.
        self.plugins        = Plugins(
                                        self,
                                        pluginbase.PluginBase("plugins"),
                                        searchpath=plugin_paths,
                                        read_on_exec=read_on_exec,
                                    )
        self.link_key       = None          # Oper-defined pass for accepting connections as server links.
        self.links          = {}            # Other servers (IRCServerLink instances) by domain or address.
        self.lines          = {             # Bans we check on client connect, against...
                               'K':{},      # A userhost, locally.
                               'G':{},      # A userhost, network-wide.
                               'Z':{},      # An IP range, locally.
                               'GZ':{}      # An IP range, network-wide.
                              }             # An example of the syntax is lines['K']['*!*@*.fr]['n!u@h', '02343240', 'Reason']
        self.link_key       = hashlib.new('sha512', str(os.urandom(128)).encode('utf-8')).hexdigest()
        self.sock.setblocking(0)
        # Avert "Address already in use" on restarts 
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(server_address)
        self.sock.listen(5)
        asyncio.Task(self._server())

    @asyncio.coroutine
    def _server(self):
        while True:
            sock, host = yield from self.loop.sock_accept(self.sock)
            client = IRCClient(self, sock, host)

    def link_server(self, client, rhost, link_key):
        """
        TODO ----------------------------------------------------------------
        Initiate a connection to a remote Psyrcd instance, identify ourselves
        as a server and synchronise state.
        TODO ----------------------------------------------------------------
        """
        return
        if not "N" in client.modes:
            client.write("You are not a Network Administrator.")
            return
        
        if rhost in self.links:
            client.write("The host %s constitutes an existing link." % rhost)
            client.write("Re-linking requires you to OPERSERV SQUIT them, first.")

        else:
            link = IRCServerLink(self, rhost, link_key)
            
            if ':' in rhost:
                rhost, rport = rhost.split(":")
            else:
                rport = 6667
            
            coro   = self.loop.create_connection(lambda: link, rhost, rport)
            future = asyncio.async(coro)
            
            self.links[":".join((rhost, rport))] = (coro, future, link)
            future.add_done_callback(link.finish)

            if link.link_active:
                client.broadcast("umode:W", ":%s NOTICE * :%s linked %s with %s." % \
                    (SRV_DOMAIN, client.client_ident(True), SRV_DOMAIN, rhost))
 
            else:
                client.broadcast("umode:W", ":%s NOTICE * :%s tried to link %s with %s." % \
                    (SRV_DOMAIN, client.client_ident(True), SRV_DOMAIN, rhost))
                client.write("A link could not be established at this time.")

    def unlink_server(self, client, rhost, *args):
        pass

    def repl(self, repl_locals={}, sysexit=0):
        """
        Spawn a debugging REPL.
        Requires Ptpython. Doesn't work if you'ved piped in an oper password.
        """
        try:
            from ptpython.repl import embed
        except ImportError:
            sys.stderr.write("Error: The --repl flag requires the ptpython library.\n")
            sys.stderr.write("This can be installed on most systems with \"sudo pip3 install ptpython\".")
            sys.exit(1)
        if not sys.stdin.isatty():
            print("Error: stdin isn't a tty.")
            sys.exit(1)
        def configure_repl(repl):
            repl.prompt_style                   = "ipython"
            repl.vi_mode                        = True
            repl.confirm_exit                   = False
            repl.show_status_bar                = False
            repl.show_line_numbers              = True
            repl.show_sidebar_help              = False
            repl.highlight_matching_parenthesis = True
            repl.use_code_colorscheme("igor")
        embed(locals=repl_locals, configure=configure_repl)
        if sysexit:
            sys.exit(0)

class ForeignClient(IRCClient):
    """
    Foreign clients are structurally identical to the IRCClient class with the
    exception that they're known to us through a remote Psyrcd instance that
    could be multiple links away. This includes emulating IRCClient.request in
    order to route messages to the correct node in the network.
    """

class IRCServerLink(asyncio.Protocol):
    """
    Represents a connection to a remote Psyrcd instance.
    """
    def __init__(self, local_server, rhost, link_key):
        self.local_server = local_server
        self.rhost        = rhost
        self.link_key     = link_key
        self.transport    = None
        self.link_active  = False

    def connection_made(self, transport):
        """
        Mark the link as active and negotiate as a server.
        """
        self.link_active = True
        self.transport   = transport
        logging.info("Connected to %s" % self.rhost)
        self.write("SERVER %s %s %s %s\n" % \
            (SRV_VERSION, SRV_DOMAIN, NET_NAME, self.link_key))

    def data_received(self, data):
        logging.info("<< %s: %s" % (self.rhost, data.decode("utf-8")))

    def write(self, *params, msgprefix=""):
        if not self.transport:
            return

        for message in map(str, params):
            for line in message.splitlines():
                logging.info(">> %s: %s" % (self.rhost, line))
                self.transport.write(line.encode("utf-8"))

    def connection_lost(self, exc):
        logging.info("! %s" % str(exc))

    def finish(self, arg):
        print(arg)
        logging.info("Connection to %s closed." % self.rhost)

    def __repr__(self):
        return "<%s IRCServerLink (%s <-> %s) at %s>" % \
            ("Active" if self.link_active else "Inactive",
            SRV_DOMAIN, self.rhost, hex(id(self)))

class Script(object):
    def __init__(self, file=None, env={}):
        self.read_on_exec = options.debug
        self.file   = file
        self.env    = env
        self.script = ''
        self.code   = None
        self.hash   = None
        self.cache  = {
            'config':{'options':         options,
                      'logging':         logging,
                      'NET_NAME':        NET_NAME,
                      'SRV_VERSION':     SRV_VERSION,
                      'SRV_DOMAIN':      SRV_DOMAIN,
                      'SRV_DESCRIPTION': SRV_DESCRIPTION,
                      'SRV_WELCOME':     SRV_WELCOME,
                      'MAX_NICKLEN':     MAX_NICKLEN,
                      'MAX_CHANNELS':    MAX_CHANNELS,
                      'MAX_TOPICLEN':    MAX_TOPICLEN,
                      'SRV_CREATED':     SRV_CREATED,
                      'MAX_CLIENTS':     MAX_CLIENTS,
                      'MAX_IDLE':        MAX_IDLE
                     }
                  }

    def execute(self,env={}):
            if not self.code or self.read_on_exec:
                self.compile()
            if env:
                self.env = env
            self.env['cache'] = self.cache
            exec(self.code,  self.env)
            del self.env['__builtins__']
            if 'cache' in self.env.keys():
                self.cache = self.env['cache']
            return(self.env)

    def compile(self,script=''):
            if self.file:
                    f = open(self.file, 'r')
                    self.script = f.read()
                    f.close()
            elif script: self.script=script
            if self.script:
                    hash = sha1sum(self.script)
                    if self.hash != hash:
                            self.hash = hash
                            self.code = compile(self.script, '<string>', 'exec')
                    self.script = ''

    def __getitem__(self, key):
            if key in self.env.keys():
                    return self.env[key]
            else:
                    raise(KeyError(key))

#        def __call__(self, client, command, params):
    def __call__(self, client, command, params):
        try:
            self.execute({'params':params,'command':command,'client':client})
            #self.execute(ctx)
            if 'output' in self.env.keys():
                return(self['output'])
        except Exception as err:
            logging.error('%s in %s' % (err,self.file))
            client.broadcast('umode:W',':%s ERROR %s found %s in %s' % \
                (SRV_DOMAIN,client.client_ident(), err, self.file))
            client.broadcast(client.nick, ':%s NOTICE %s :%s is temporarily out of order.' % \
                (SRV_DOMAIN, client.nick, command.upper()))

class Plugin(dict):
    def __init__(self, module, **kwargs):
        self["cache"]  = {}
        self["module"] = module
        
        # Keep a record of this modules' SHA1
        with open(module.__file__, "r") as f:
            self["hash"] = sha1sum(f.read())

        dict.__init__(self, **kwargs)

    @property
    def module_name(self):
        return self["module"].__name__.split(".")[-1]

    def get_hash(self):
        with open(self["module"].__file__, "r") as f:
            return sha1sum(f.read())
    
    def __name__(self):
        if "callable" in self and hasattr(self["callable"], "__name__"):
            return self["callable"].__name__
        return None
    
    def __call__(self, ctx, *args, **kwargs):
        #
        # If you're wondering how read_on_exec works for Plugins it's in
        # IRCServer.handle and the scripts decorator, just before this
        # method is invoked.
        #
        if not "callable" in self:
            raise Exception("No callable loaded in %s" % repr(self))

        return self["callable"](ctx, *args, **kwargs)

    def __repr__(self):
        return "<Plugin %s:%s at %s>" % \
            (self["type"], self["name"], hex(id(self)))

class Plugins(pluginbase.PluginSource):
    """
    Plugins available at self.mod. I.e. self.load("foo") loads foo onto self.mod.foo.

    """
    def __init__(self, server, base, identifier=None, searchpath=None,
                 read_on_exec=False, persist=True):
        self.commands     = {}
        self.cmodes       = {}
        self.umodes       = {}
        self.server       = server
        self.read_on_exec = read_on_exec
        self.list_available_plugins = self.list_plugins
        pluginbase.PluginSource.__init__(self, base, identifier, searchpath, persist)

    def load(self, plugin_name: str, config={}, reload=True) -> bool:
        """

        """
        if reload and plugin_name in dir(self.mod):
            module = getattr(self.mod, plugin_name)
            importlib.reload(module)
        else:
            module = self.load_plugin(plugin_name)

        if not hasattr(module, "__package__"):
            raise Exception("Missing __package__ attribute in plugin %s." % plugin_name)
        
        # Plugins may also have callables named __init__ and __del__ that we
        # send a ScriptContext containing a reference to the IRCServer into.
        # This permits Plugins to manage the entire lifecycle of their state.
        if callable(getattr(module, "__init__", None)):
            module.__init__(
                ScriptContext(config=config, server=self.server),
            )

        def _load(module, pkginfo):
            """
            Obtain package info. Equivalent to returning a provides line from a
            script except plugins are expected to store this information in the
            top-level __package__ variable.
            
            The structure is one of
            
              __package__ = {"name": "foo", "type": "umode",
                             "description": "desc", "callable": callable}
            or
              __package__ = [{"name": "foo",
                              "type": "umode",
                              "description": "desc",
                              "callable": callable},
                              ...]
            
            """
            dictionary = getattr(self, pkginfo["type"] + "s")

            if not reload and pkginfo["name"] in dictionary:
                raise Exception("Plugin %s overlaps with an already loaded plugin (%s %s)." % \
                    (plugin_name, pkginfo["type"], pkginfo["name"]))
                
            plugin = Plugin(module, **pkginfo)
            plugin["read_on_exec"] = self.read_on_exec

            name = pkginfo["name"]
            if name in dictionary:
                item = dictionary[name]
                print(item["hash"])

            dictionary[pkginfo["name"]] = plugin
            logging.info("Loaded (plugin) %s %s (%s)." % \
                (plugin["type"], plugin["name"], plugin["description"]))
        
        if isinstance(module.__package__, dict):
            _load(module, module.__package__)

        elif isinstance(module.__package__, (list, tuple, set)):
            for pkginfo in module.__package__:
                _load(module, pkginfo)

    def unload(self, plugin: str) -> bool:
        # Plugins may also have callables named __init__ and __del__ that we
        # send a ScriptContext containing a reference to the IRCServer into.
        # This permits Plugins to manage the entire lifecycle of their state.
        if callable(getattr(plugin, "__del__", None)):
            plugin.__del__(
                ScriptContext(server=self.server),
            )
            return True
        return False

    def init(self, config: dict) -> bool:
        for plugin_name in self.list_plugins():
            self.load(plugin_name, config=config)

    def exit(self):
        for plugin_name in self.list_plugins():
            self.unload(plugin_name)

    @property
    def as_table(self):
        """
        print(client.server.plugins.as_table, file=client)
        """
        pass

    def __repr__(self):
        return "<Plugins at %s>" % hex(id(self))

class Scripts(object):
    def __init__(self, server=None):
        self.server   = server
        self.dir      = scripts_dir
        self.server   = 0
        self.commands = {}
        self.cmodes   = {}
        self.umodes   = {}
        self.threads  = []
        self.i        = {'commands': self.commands,
        'cmodes': self.cmodes, 'umodes': self.umodes}

    def load(self, script, client=None):
        """
        Executes a script with init namespace,
        Determines if it's already loaded,
        Places into the correct dictionary.
        """
        try:
            provides, s = self.init(script, client, True)
        except Exception as err:
            logging.error(err)
            return

        err = None
        for item in provides:
            description = 'No description.'
            d = item.split(':')
            if len(d) > 2:
                description=d[2]
            if d[0] == 'command':
                for i in d[1].split(','):
                    if i in self.commands.keys():
                        err = "%s appears to already be loaded." % i
                    else:
                        self.commands[i] = [s, description]
                    if client:
                        client.broadcast(client.nick,
                        	':%s NOTICE %s :Loaded %s %s (%s)' % \
                        	(SRV_DOMAIN, client.nick, d[0], i, description))
                    logging.info('Loaded (script) %s %s (%s)' % (d[0], i, description))
            
            elif d[0] == 'cmode':
                for i in d[1].split(','):
                    if i in self.cmodes:
                        err = "%s appears to already be loaded." % i
                    else:
                        self.cmodes[i] = [s, description]
                        if self.server:
                            for channel in self.server.channels.values():
                                channel.supported_modes[i] = description
                    if client: client.broadcast(client.nick,
                        ':%s NOTICE %s :Loaded %s %s (%s)' % \
                        (SRV_DOMAIN,client.nick,d[0],i, description))
                    logging.info('Loaded (script) %s %s (%s)' % (d[0], i, description))
            
            elif d[0] == 'umode':
                for i in d[1].split(','):
                    if i in self.umodes:
                        err = "%s appears to already be loaded." % i
                    else:
                        self.umodes[i] = [s, description]
                        if self.server:
                            for user in self.server.clients.values():
                                user.supported_modes[i] = description
                    if client: client.broadcast(client.nick, ':%s NOTICE %s :Loaded %s %s (%s)' % \
                        (SRV_DOMAIN,client.nick,d[0],i, description))
                    logging.info('Loaded (script) %s %s (%s)' % (d[0],i, description))
            else:
                err = "%s doesn't provide anything I can recognize." % (self.dir+script)
                if client: client.broadcast(client.nick,":%s NOTICE %s :%s" % (SRV_DOMAIN,client.nick,err))
                logging.error(err)

    def unload(self, script, client=None, force=False):
        try:
            provides = self.init(script, client, loading=False)
        except:
            return
        err = ''
        if not provides:
            return
        for item in provides:
            description = 'No description.'
            d = item.split(':')
            if len(d) > 2:
                description = d[2]
            
            if d[0] == 'command':
                for i in d[1].split(','):
                    if i in self.commands:
                        del self.commands[i]
                        err = "Unloaded %s %s (%s)" % (d[0], i, description)
                        if client: client.broadcast(client.nick,":%s NOTICE %s :%s" % \
                            (SRV_DOMAIN, client.nick, err))
                        logging.info(err)
            
            elif d[0] == 'cmode':
                for i in d[1].split(','):
                    if i in self.cmodes:
                        if self.server:
                            for channel in self.server.channels.values():
                                if i in channel.supported_modes:
                                    del channel.supported_modes[i]
                                if i in channel.modes:
                                    # ns={'set':False}
                                    if client: client.broadcast(channel.name,':%s MODE %s -%s' % \
                                        (SRV_DOMAIN, channel.name, i))
                                    del channel.modes[script]
                        del self.cmodes[i]
                        err = "Unloaded %s %s (%s)" % (d[0], i, description)
                        if client: client.broadcast(client.nick,":%s NOTICE %s :%s" % \
                            (SRV_DOMAIN, client.nick, err))
                        logging.info(err)

            elif d[0] == 'umode':
                for i in d[1].split(','):
                    if i in self.umodes:
                        if self.server:
                            for user in self.server.clients.values():
                                if i in user.supported_modes:
                                    del user.supported_modes[i]
                                if i in user.modes:
                                    if client: client.broadcast(client.nick,':%s MODE %s -%s' % \
                                        (SRV_DOMAIN, user.nick, i))
                                    del user.modes[i]
                    del self.umodes[i]
                    err = "Unloaded %s %s (%s)" % (d[0],i,description)
                    if client: client.broadcast(client.nick,":%s NOTICE %s :%s" % \
                        (SRV_DOMAIN, client.nick, err))
                    logging.info(err)
            else:
                err = "%s doesn't provide anything I can recognize." % (self.dir+script)
                if client: client.broadcast(client.nick,":%s NOTICE %s :%s" % \
                    (SRV_DOMAIN, client.nick, err))
                logging.error(err)

    def init(self, script, client=None, return_script=False, loading=True):
        if self.dir:
            script = Script(self.dir+script)
        else:
            raise Exception('self.dir undefined.')
        try:
            script.execute({'init': loading, 'client': client, 'server': self.server})
        except Exception as err:
            if not client:
                logging.error('%s in %s' % (err, script.file))
            else:
                client.broadcast(client.nick, ':%s NOTICE %s :%s in %s' % \
                    (SRV_DOMAIN, client.nick, err, script.file))
            return
        provides = []
        if 'provides' in script.env.keys():
            if isinstance(script['provides'], (str, bytes)):
                provides.append(script['provides'])
            elif isinstance(script['provides'], list):
                provides = script['provides']
            else:
                if client:
                    client.broadcast(client.nick,
                    ":%s NOTICE %s :Incorrect type %s used to contain 'provides' in %s" % \
                    (SRV_DOMAIN, client.nick, type(script['provides']), script.file))
                else:
                    logging.error("Incorrect type %s used to contain 'provides' in %s" % \
                    (type(s['provides']), script.file))
                return
            if return_script:
                return (provides, script)
            return provides

def ping_routine(EventLoop):
    """
    Check client idle times every PING_FREQUENCY seconds.

    Clients are responsible for sending periodic PING messages to the server,
    which is tasked with then responding with a PONG to let the client know
    we care.

    This routine is to remove connections that are either unresponsive or
    not playing this game.
    """
    for client in EventLoop.server.clients.copy().values():
        then = int(client.last_activity)
        now = int(str(time.time())[:10])
        if (now - then) > MAX_IDLE:
            client.finish(response = ':%s QUIT :Ping timeout. Idle %i seconds.' % \
                (client.client_ident(True), now - then))

    EventLoop.call_later(PING_FREQUENCY, ping_routine, EventLoop)

class ConfigurationError(Exception):
    """
    Exception thrown for configuration errors.
    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return(repr(self.value))

def apply_config(config):
    """
    `apply_config` maps blocks of HCL to globals that are used throughout
    the IRCD.
    """
    # NOTE: The logging module is available globally if you'd
    #       like to define formatting in the configuration file.
    # There's also nothing stopping you from applying multiple configs.
    if "oper" in config:
        oper_block = config["oper"]
        # NOTE(ljb): Should be a list of username / password_hash tuples.
        if "username" in oper_block:
            global OPER_USERNAME
            if oper_block["username"] == True:
                OPER_USERNAME = os.getenv("USER")
            else:
                OPER_USERNAME = oper_block["username"]

        if "password" in oper_block:
            global OPER_PASSWORD
            OPER_PASSWORD = oper_block["password"]

    if not "server" in config:
        raise ConfigurationError("\"server\" block missing from Psyrcd configuration.")
    
    server_block = config["server"]

    if isinstance(server_block, dict):
        config["server"] = ScriptContext(**server_block)
    
    if "name" in server_block:
        global SRV_NAME
        SRV_NAME = server_block["name"]
    if "domain" in server_block:
        global SRV_DOMAIN
        SRV_DOMAIN = server_block["domain"]
    if "description" in server_block:
        global SRV_DESCRIPTION
        SRV_DESCRIPTION = server_block["description"]
    if "welcome" in server_block:
        global SRV_WELCOME
        SRV_WELCOME = server_block["welcome"].format(SRV_NAME)

    if "ping_frequency" in server_block:
        global PING_FREQUENCY
        PING_FREQUENCY = server_block["ping_frequency"]

    if not "max" in config["server"]:
        raise ConfigurationError("\"max\" block missing from \"server\" block in Psyrcd configuration.")

    max_block = server_block["max"]
    
    if isinstance(server_block["max"], dict):
        config["server"]["max"] = ScriptContext(**max_block)
    
    if "channels" in max_block:
        global MAX_CHANNELS
        MAX_CHANNELS = max_block["channels"]
    if "clients" in max_block:
        global MAX_CLIENTS
        MAX_CLIENTS = max_block["clients"]
    if "idle_time" in max_block:
        global MAX_IDLE
        MAX_IDLE = max_block["idle_time"]
    if "nicklen" in max_block:
        global MAX_NICKLEN
        MAX_NICKLEN = max_block["nicklen"]
    if "topiclen" in max_block:
        global MAX_TOPICLEN
        MAX_TOPICLEN = max_block["topiclen"]

    # Return an object with simple attribute lookup semantics
    # 
    # Permits things like `self.server.config.server.max.clients` from
    # instances of `IRCClient`.
    #
    # Only caveat is the special handling of keys named "line" as we're reusing
    # `ScriptContext`.
    #
    return ScriptContext(**config)

def sha1sum(data): return(hashlib.sha1(data.encode('utf-8')).hexdigest())

class tabulate(object):
    "Print a list of dictionaries as a table"
    def __init__(self, fmt, sep=' ', ul=None):
        super(tabulate,self).__init__()
        self.fmt   = str(sep).join('{lb}{0}:{1}{rb}'.format(key, width, lb='{', rb='}') for heading,key,width in fmt)
        self.head  = {key:heading for heading,key,width in fmt}
        self.ul    = {key:str(ul)*width for heading,key,width in fmt} if ul else None
        self.width = {key:width for heading,key,width in fmt}
    def row(self, data):
        return(self.fmt.format(**{ k:str(data.get(k,''))[:w] for k,w in self.width.items() }))
    def __call__(self, dataList):
        _r = self.row
        res = [_r(data) for data in dataList]
        res.insert(0, _r(self.head))
        if self.ul:
            res.insert(1, _r(self.ul))
        return('\n'.join(res))

def format(data):
    fmt=[]
    tmp={}
    r_append=0
    for item in data:
        for key,value in item.items():
            if not key in tmp.keys():
                if value: tmp[key] = len(str(value))
            elif len(str(value)) > tmp[key]:
                if value: tmp[key] = len(str(value))
    for key,value in tmp.items():
        if (key == 'Hash') or (key =='State'): r_append=(key,key,value)
        else: fmt.append((key, key, value))
    if r_append: fmt.append(r_append)
    return(fmt)

def tconv(seconds):
    minutes, seconds = divmod(seconds, 60)
    hours,   minutes = divmod(minutes, 60)
    days,    hours   = divmod(hours,   24)
    weeks,   days    = divmod(days,     7)
    months,  weeks   = divmod(weeks,    4)
    years,   months  = divmod(months,  12)
    s = ""
    if years:
        if years == 1: s+= "%i year, " % (years)
        else: s+= "%i years, " % (years)
    if months:
        if months == 1: s+= "%i month, " % (months)
        else: s+= "%i months, " % (months)
    if weeks:
        if weeks == 1: s+= "%i week, " % (weeks)
        else: s+= "%i weeks, " % (weeks)
    if days:
        if days == 1: s+= "%i day, " % (days)
        else: s+= "%i days, " % (days)
    if hours:
        if hours == 1: s+= "%i hour " % (hours)
        else: s+= "%i hours " % (hours)
    if minutes:
        if len(s) > 0:
            if minutes == 1: s+= "and %i minute" % (minutes)
            else: s+= "and %i minutes" % (minutes)
        else:
            if minutes == 1: s+= "%i minute" % (minutes)
            else: s+= "%i minutes" % (minutes)
    if s == '':
        s = 'a few seconds'
    return s

# Fork a child and end the parent (detach from parent)
# Change some defaults so the daemon doesn't tie up dirs, etc.
class Daemon:
    def __init__(self, pidfile):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0) # End parent
        except OSError as e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(-2)
        os.setsid()
        os.umask(0)
        try:
            pid = os.fork()
            if pid > 0:
                try: 
                    # TODO: Read the file first and determine if already running.
                    f = open(pidfile, 'w')
                    f.write(str(pid))
                    f.close()
                except IOError as e:
                    logging.error(e)
                    sys.stderr.write(repr(e))
                sys.exit(0) # End parent
        except OSError as e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(-2)
        for fd in (0, 1, 2):
            try:
                os.close(fd)
            except OSError:
                pass

def re_to_irc(r, displaying=True):
    if displaying:
        r = re.sub('\\\.','.',r)
        r = re.sub('\.\*','*',r)
    else:
        r = re.sub('\.','\\\.',r)
        r = re.sub('\*','.*',r)
    return(r)

# TODO: memoize
def lookup(addr):
    try:
        return(socket.gethostbyaddr(addr)[0])
    except:
        return(None)

class color:
    purple = '\033[95m'
    blue = '\033[94m'
    green = '\033[92m'
    orange = '\033[93m'
    red = '\033[91m'
    end = '\033[0m'
    def disable(self):
        self.purple = ''
        self.blue = ''
        self.green = ''
        self.orange = ''
        self.red = ''
        self.end = ''

if __name__ == "__main__":
    prog = "psyrcd"
    description = "The %sPsybernetics%s IRC Server." % (color.orange,color.end)
    epilog = "Using the %s-k%s and %s-c%s options together enables SSL and plaintext connections over the same port." % \
        (color.blue,color.end,color.blue,color.end)

    parser = argparse.ArgumentParser(prog=prog, description=description, epilog=epilog, usage=argparse.SUPPRESS)
    parser.add_argument('--version', action='version', version=SRV_VERSION)
    parser.add_argument("--start",            dest="start", action="store_true",
        default=True, help="(default)")
    parser.add_argument("--stop",             dest="stop", action="store_true",
        default=False)
    parser.add_argument("--restart",          dest="restart", action="store_true",
        default=False)
    parser.add_argument("--pidfile",          dest="pidfile", action="store",
        default='psyrcd.pid')
    parser.add_argument("--logfile",          dest="logfile", action="store",
        default=None)
    parser.add_argument("-a", "--address",    dest="listen_address",
        action="store", default='0.0.0.0')
    parser.add_argument("-p", "--port",       dest="listen_port", action="store",
        default='6667')
    parser.add_argument("--disable-logging",  dest="disable_logging",
        action="store_true", default=False)
    parser.add_argument("-f", "--foreground", dest="foreground",
        action="store_true")
    parser.add_argument("--config",           dest="config", action="store_true", 
        default="psyrcd.conf", help="(defaults to \"psyrcd.conf\")")
    parser.add_argument("--run-as",           dest="run_as", action="store",
        default=None, help="(defaults to the invoking user)")
    parser.add_argument("--scripts-dir",      dest="scripts_dir",action="append",
        default=['scripts'], help="(defaults to ./scripts/)")
    parser.add_argument("--plugin-paths",     dest="plugin_paths",action="append",
        default=['plugins'], help="(defaults to ./plugins/)")
    parser.add_argument("--preload",          dest="preload",
        action="store_true", default=False,
        help="Preload all available scripts.")
    parser.add_argument("--debug",            dest="debug", action="store_true",
        default=False, help="Sets read_on_exec to True for live development.")
    parser.add_argument("-k", "--key",        dest="ssl_key",action="store",
        default=None)
    parser.add_argument("-c", "--cert",       dest="ssl_cert",action="store",
        default=None)
    parser.add_argument("--ssl-help",         dest="ssl_help",action="store_true",
        default=False)
#    parser.add_option("--link-help",       dest="link_help",action="store_true",default=False)
    options = parser.parse_args()

    if options.ssl_help:
        print("""Keys and certs can be generated with:
$ %sopenssl%s genrsa 4096 >%s key%s
$ %sopenssl%s req -new -x509 -nodes -sha256 -days 365 -key %skey%s > %scert%s""" % \
    (color.blue, color.end, color.orange, color.end, color.blue, color.end,
    color.orange, color.end, color.orange, color.end))
        raise SystemExit

    if options.disable_logging:
        del logging
        def logging(*args, **kwargs): pass
        logging.info  = lambda x: x
        logging.error = logging.info
        logging.debug = logging.info
    else:
       if options.logfile:
           logfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),options.logfile)
           log = logging.basicConfig(
               level=logging.DEBUG,
               format='%(asctime)s [%(levelname)s] %(message)s',
               filename=logfile,
               filemode='a')
       else:
           log = logging.basicConfig(
               level=logging.DEBUG,
               format='%(asctime)s [%(levelname)s] %(message)s')

    # Handle start/stop/restart commands.
    if options.stop or options.restart:
        pid = None
        try:
            f = open('psyrcd.pid', 'r')
            pid = int(f.readline())
            f.close()
            os.unlink('psyrcd.pid')
        except ValueError as e:
            sys.stderr.write('Error in pid file `psyrcd.pid`. Aborting\n')
            sys.exit(-1)
        except IOError as e:
            pass

        if pid:
            os.kill(pid, 15)
        else:
            sys.stderr.write('psyrcd not running or no PID file found\n')

        if not options.restart:
            sys.exit(0)

    if options.logfile:
        console = logging.StreamHandler()
        formatter = logging.Formatter('[%(levelname)s] %(message)s')
        console.setFormatter(formatter)
        console.setLevel(logging.DEBUG)
        logging.getLogger('').addHandler(console)

    if (pwd.getpwuid(os.getuid())[2] == 0) and (options.run_as == None):
        logging.info("Running as root is not permitted.")
        logging.info("Please use --run-as")
        raise SystemExit

    # Read and apply the configuration file.
    with open(options.config, "r") as fd:
        config = hcl.load(fd)

    config = apply_config(config)

    if OPER_PASSWORD == True:
        OPER_PASSWORD = hashlib.new('sha512', str(os.urandom(20))\
                            .encode('utf-8')).hexdigest()[:20]

    if not sys.stdin.isatty():
        OPER_PASSWORD = sys.stdin.read().strip('\n').split(' ',1)[0]

    if options.run_as:
        try:
            uid = pwd.getpwnam(options.run_as)[2]
            os.setuid(uid)
            logging.info("Now running as %s." % options.run_as)
            if OPER_USERNAME == None:
                OPER_USERNAME = options.run_as
        except:
            logging.info("Couldn't switch to user %s" % options.run_as)
            raise SystemExit

    # Detach from console, reparent to init
    if not options.foreground:
        print("Netadmin login: %s/oper %s %s%s" % \
            (color.green, OPER_USERNAME, OPER_PASSWORD, color.end))
        Daemon(options.pidfile)
    else:
        logging.debug("Netadmin login: %s/oper %s %s%s" % \
            (color.green, OPER_USERNAME, OPER_PASSWORD, color.end))

    # Hash the password in memory.
    OPER_PASSWORD = hashlib.sha512(OPER_PASSWORD.encode('utf-8')).hexdigest()

    if options.ssl_cert and options.ssl_key:
        logging.info("SSL Enabled.")

    if options.logfile:
        logging.info("Logging to %s" % (logfile))

    # Set variables for processing script files:
    for scripts_dir in options.scripts_dir:
        this_dir = os.path.abspath(os.path.curdir) + os.path.sep
        scripts_dir = this_dir + scripts_dir + os.path.sep
        if os.path.isdir(scripts_dir):
            logging.info("Scripts directory: %s" % scripts_dir)
        else:
            scripts_dir = False

    # Ready a server instance.
    if uvloop != None:
        asyncio.set_event_loop(uvloop.new_event_loop())
    
    ThreadPool = ThreadPoolExecutor(MAX_CLIENTS)
    EventLoop  = asyncio.get_event_loop()
    ircserver  = IRCServer(
                    EventLoop,
                    config,
                    (options.listen_address, int(options.listen_port)),
                    options.plugin_paths,
                    read_on_exec=options.debug,
    )

    # Start.
    try:
        if options.preload:
            if options.plugin_paths:
                ircserver.plugins.init(config)
            
            if scripts_dir:
                for filename in os.listdir(scripts_dir):
                    if os.path.isfile(scripts_dir + filename):
                        ircserver.scripts.load(filename)

        ircserver.loop.call_later(PING_FREQUENCY, ping_routine, EventLoop)
        logging.info('Starting psyrcd on %s:%s' % \
            (options.listen_address, options.listen_port))
        ircserver.loop.set_debug(options.debug)
        ircserver.loop.run_forever()
    except socket.error as e:
        logging.error(repr(e))
        sys.exit(-2)
    except KeyboardInterrupt:
        ircserver.loop.stop()
        ThreadPool.shutdown()
        if options.preload and scripts_dir:
            scripts = []
            for x in ircserver.scripts.i.values():
                for script in x.values():
                    scripts.append(script[0].file)
            scripts = set(scripts)
            for script in scripts:
                ircserver.scripts.unload(script[script.rfind(os.sep)+1:])
        logging.info('Bye.')
        raise SystemExit
