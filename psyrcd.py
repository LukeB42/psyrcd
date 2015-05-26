#!/usr/bin/env python 
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
#   - Check the PID file on startup. Issue a warning and raise SystemExit if psyrcd is already running.
#   - Implement /notice and possibly /userhost
#   - Implement all user and channel modes.
#   - Fix TODO comments.
# Scripting:
#   - /operserv scripts                      Lists all loaded scripts. Indicates file modifications if --debug isn't being used.
#   - /operserv scripts list                 Lists all available scripts.
#   - /operserv scripts load scriptname      Loads the specified file as a code object using a specific namespace, where a variable called 'init' is set to True.
#   - /operserv scripts unload scriptname    Unloads the specified file by executing its code object with 'init' set to False.
#                                            This indicates that file handles in the cache must be closed and structures on affected objects ought to be removed.
#
#   - namespace = {'client':self,['channel':channel],['mode':mode/'params':params],['set':bool,'args':args/'display':True],['line':line,'func':func]}
#   - Modes can be any number of characters long. Modes are entries in a dictionary, called channel.modes and user.mdoes. Mode arguments are stored in lists by default.
#   - The structure on a channel or user object looks like user.modes['scriptmode'], where 'scriptmode' points to a list or whatever structure your script manually sets.
#   - The type used to store arguments can be overridden and the way values are appended and removed can be handled from within scripts.
#   - Mode parameters can be stored in Numpy arrays for example. If you have a mode called numpy, you could do something like: /mode #channel +numpy:123,456,789,0
#   - /mode #channel -numpy: would clear the mode completely, rather than removing individual parameters and then the mode itself.
#   - init and unload ought to cause the script to create or remove structures on channels and clients.
#   - Modes on load are automatically appended to the necessary supported_modes dictionary and removed on unload.
#   - Mode scripts can check for the presence of a variable named "display" in their namespace in order to return custom messages in a variable named "output".
#   - @scripts decorator cycles through modes and match to server.scripts.u/cmodes.keys().
#   - Every time a channel name is the target of a command its modes are checked against IRCServer.Scripts.cmodes.
#   - Decorator on handle_* will send `self,channel,func,params` into your scripts default namespace.
#   - For example: /mode #channel +lang:en
#   - channel.modes{'l':['50'],'lang':['en'],'n':1,'t':1}
# The Future:
#   - /operserv connect server:port key; generate key at runtime.
#   - Connect and negotiate as a server, hand connection off to dedicated class.
#   - Someone is going to have to disable their scripts.
#   - Determine the most elegant way of performing breadth-first search with as little stateful info as possible
#   - decorate .broadcast() so it transmits messages across server links. Recipients parse joins/parts/quits
# Known Errors:
#   - Windows doesn't have fork(). Run in the foreground or Cygwin.

import sys, os, re, pwd, time, optparse, logging, hashlib, SocketServer, socket, select, ssl

NET_NAME        = "psyrcd-dev"
SRV_VERSION     = "psyrcd-0.15"
SRV_DOMAIN      = "irc.psybernetics.org.uk"
SRV_DESCRIPTION = "I fought the lol, and. The lol won."
SRV_WELCOME     = "Welcome to %s" % NET_NAME
SRV_CREATED     = time.asctime()

MAX_CLIENTS   = 300     # User connections to be permitted before we start denying new connections.
MAX_IDLE      = 300     # Time in seconds a user may be caught being idle for.
MAX_NICKLEN   = 12      # Characters per available nickname.
MAX_CHANNELS  = 200     # Channels per server on the network.
MAX_TOPICLEN  = 512     # Characters per channel topic.
MAX_TICKS     = [0,15]  # select()s through active connections before we start pruning for ping timeouts

OPER_USERNAME = os.environ.get('USER', None)
OPER_PASSWORD = True    # Set to True to generate a random password, False to disable the oper system, a string of your choice or pipe one at runtime:
                        # openssl rand -base64 32 | ./psyrcd --preload -f

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
        self.code = code
        self.value = value

    def __str__(self):
        return (repr(self.value))


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
        self.supported_modes = {
            # Uppercase modes can only be set and removed by opers.
            'A': "Server administrators only.",
            'i': "Invite only.",
            'm': "Muted.",
            'n': "No messages allowed from users who are not in the channel.",
            'g': "Hide channel operators.",
            'v': "Voiced. Cannot be muted.",
            'h': "Channel half-operators.",
            'o': "Channel operators.",
            'a': "Channel administrators.",
            'q': "Channel owners.",
            'b': "Channel bans.",
            'e': "Exceptions to channel bans.",
            'O': "Server operators only.",
            'p': "Private. Hides channel from /whois.",
            'r':
            "[redacted] Redacts usernames and replaces them with the first word in this line.",
            # supported_modes['r'].split()[0]
            #            'l':"Limited amount of users.",
            #            'k':"Password protected.",
            's': "Secret. Hides channel from /list.",
            't': "Only operators may set the channel topic.",
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
        self.ops = [self.modes['v'], self.modes['h'], self.modes['o'],
                    self.modes['a'], self.modes['q']]
#     # modes['b'] ==> 'mask_regex setter_nick unix_time' -> i.split()[0]

    def __repr__(self):
        return ('<%s %s at %s>' % (self.__class__.__name__, self.name,
                                   hex(id(self))))


class IRCOperator(object):
    """
    Object holding stateful info and commands relevant to policing the server from inside.
    """

    def __init__(self, client):
        self.client = client  # So we can access everything relavent to this oper
        self.vhost = "internet"
        self.modes = ['O', 'Q', 'S', 'W']  # Set on client once authed
        self.passwd = None

    def dispatch(self, params):
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
            return (response)
        except Exception, e:
            return ('Internal Error: %s' % e)

    def handle_seval(self, params):
        if 'A' in self.client.modes:
            message = ': %s' % (eval(params))
            return (message)

    def handle_setkey(self, params):
        """
        Defines the passphrase a foreign server must transmit to us in order to synchronise a link.
        Linking is disabled by default until a local passphrase is defined.
        /operserv setkey server-link-passphrase
        """
        if 'N' in self.client.modes:
            self.client.server.link_key = params
            response = ': Server link key set to "%s"' % params
            self.client.broadcast(self.client.nick, response)
        else:
            response = ': You need to be a network administrator to do that.'
            self.client.broadcast(self.client.nick, response)

    def handle_sconnect(self, params):
        """
        Connect to another instance of psyrcd and attempt to synchronise objects.
        /operserv sconnect hostname[:port] remote-passphrase
        """
        response = ": Work in progress. Brace for impact."
        self.client.broadcast(self.client.nick, response)

    def handle_dump(self, params):
        """
        Dump internal server info for debugging.
        """
        # TODO: Phase this out in favour of /stats
        # TODO: Show modes, invites, excepts, bans.
        response = ':%s NOTICE %s :Clients: %s' % (
            SRV_DOMAIN, self.client.nick, self.client.server.clients)
        self.client.broadcast(self.client.nick, response)
        for client in self.client.server.clients.values():
            response = ':%s NOTICE %s :  %s' % (SRV_DOMAIN, self.client.nick,
                                                client)
            self.client.broadcast(self.client.nick, response)
            for channel in client.channels.values():
                response = ':%s NOTICE %s :    %s' % (
                    SRV_DOMAIN, self.client.nick, channel.name)
                self.client.broadcast(self.client.nick, response)
        response = ':%s NOTICE %s :Channels: %s' % (
            SRV_DOMAIN, self.client.nick, self.client.server.channels)
        self.client.broadcast(self.client.nick, response)
        for channel in self.client.server.channels.values():
            response = ':%s NOTICE %s :  %s %s' % (
                SRV_DOMAIN, self.client.nick, channel.name, channel)
            self.client.broadcast(self.client.nick, response)
            for client in channel.clients:
                response = ':%s NOTICE %s :    %s %s' % (
                    SRV_DOMAIN, self.client.nick, client.nick, client)
                self.client.broadcast(self.client.nick, response)

    def handle_addoper(self, params):
        """
        Handles adding another serverwide oper.
        Usage: /operserv addoper oper_name passwd
        """
        nick, password = params.split(' ', 1)
        user = self.client.server.clients.get(nick)
        if not user:
            return (':%s NOTICE %s : Invalid user.' %
                    (SRV_DOMAIN, self.client.nick))
        self.client.server.opers[user.nick] = IRCOperator(user)
        oper = self.client.server.opers.get(user.nick)
        if password:
            oper.passwd = hashlib.sha512(password).hexdigest()
        response = ':%s NOTICE %s :Created an oper account for %s.' % (
            SRV_DOMAIN, self.client.nick, user.nick)
        self.client.broadcast(self.client.nick, response)

    def handle_flood(self, params):
        """
        Flood a channel with a given text file.
        """
        channel, file = params.split(' ', 1)
        if os.path.exists(file):
            fd = open(file)
            for line in fd:
                message = ':%s PRIVMSG %s %s' % (self.client.client_ident(),
                                                 channel, line.strip('\n'))
                self.client.broadcast(channel, message)
        else:
            response = ':%s NOTICE %s :%s does not exist.' % (
                SRV_DOMAIN, self.client.nick, file)
            self.client.broadcast(self.client.nick, response)

    def handle_scripts(self, params):
        """
        List, Load and Unload serverside scripts.
        """
        if not 'A' in self.client.modes: return (': IRC Administrators only.')
        if ' ' in params: cmd, args = params.split(' ', 1)
        else:
            cmd = params
            args = ''
        s = self.client.server.scripts
        if cmd == 'scripts':  # /operserv scripts (lists loaded)
            tmp = data = []
            for type, array in s.i.items():
                for name, script in array.items():
                    tmp = {}
                    if type == 'commands': tmp['Name'] = '/' + name
                    if type == 'umodes': tmp['Name'] = 'umode:' + name
                    if type == 'cmodes': tmp['Name'] = 'cmode:' + name
                    tmp['Descripton'] = script[1]
                    tmp['File'] = script[0].file.split(os.path.sep)[-1]
                    if not options.debug:
                        f = file(script[0].file, 'r')
                        hash = sha1sum(f.read())
                        f.close()
                        if hash != script[0].hash:
                            tmp['File'] = tmp['File'] + '*'
                    tmp['Hash'] = script[0].hash
                    data.append(tmp)
            fmt = format(data)
            table = tabulate(fmt, ul='-')(data)
            if not table: table = "There are no scripts loaded."
            for line in table.split('\n'):
                self.client.msg(line)
            del fmt, table, data, tmp
        elif cmd == 'list':  # /operserv scripts list (lists available)
            data = []
            if s.dir:
                files = os.listdir(s.dir)
                for filename in files:
                    if os.path.isdir(s.dir + filename): continue
                    tmp = {}
                    tmp['File'] = filename
                    tmp['State'] = 'UNLOADED'
                    for type, array in s.i.items():
                        for name, script in array.items():
                            if script[0].file.split(os.path.sep)[-
                                                                 1] == filename:
                                tmp['State'] = 'LOADED'
                                break
                    data.append(tmp)
                fmt = format(data)
                table = tabulate(fmt, ul='-')(data)
                if not table: table = "There are no scripts in %s." % s.dir
                for line in table.split('\n'):
                    self.client.msg(line)
                del fmt, table, data, tmp
            else:
                self.client.msg(
                    'A nonexistent path was defined as the scripts directory.')
        elif cmd == 'load':
            s.load(args, self.client)
        elif cmd == 'unload':
            s.unload(args, self.client)


def scripts(func):
    def wrapper(self, *args, **kwargs):

        # Comment out the following line if you want to
        # script the commands executed on connect.
        if not self.user: return (func(self, *args))

        s = self.server.scripts

        for mode in self.modes.copy():
            params = ''
            if args: params = str(args[0])
            if mode in s.umodes:
                script = s.umodes[mode][0]
                try:
                    script.execute({
                        'client': self,
                        'params': params,
                        'mode': mode,
                        'func': func
                    })
                    if 'cancel' in script.env: return ()
                    if 'params' in script.env: args = (script['params'], )
                except Exception, err:
                    logging.error('%s in %s' % (err, script.file))
                    self.broadcast('umode:W', ':%s ERROR %s found %s in %s' % \
                    (SRV_DOMAIN, self.client_ident(), err, script.file))

        if params.startswith('#'):
            if ' ' in params:
                channel = self.server.channels.get(params.split()[0])
            else:
                channel = self.server.channels.get(params)
            if channel:
                for mode in channel.modes.copy():
                    params = ''
                    if args: params = str(args[0])
                    if mode in s.cmodes:
                        script = s.cmodes[mode][0]
                        try:
                            script.execute({
                                'client': self,
                                'channel': channel,
                                'params': params,
                                'mode': mode,
                                'func': func
                            })
                            if 'cancel' in script.env:
                                if type(script['cancel']) == str:
                                    return (script['cancel'])
                                else:
                                    return ('')
                            if 'params' in script.env:
                                args = (script['params'], )
                        except Exception, err:
                            logging.error('%s in %s' % (err, script.file))
                            self.broadcast('umode:W', ':%s ERROR %s found %s in %s' % \
                            (SRV_DOMAIN, self.client_ident(), err, script.file))
        return (func(self, *args))

    wrapper.__doc__ = func.__doc__
    return (wrapper)


def disabled(func):
    def wrapper(self, *args):
        #        command = func.func_name.strip('handle_').upper()
        #        return(':%s is not available on this server.' % command)
        return ('')

    return (wrapper)


def links(target):
    def wrapper(self, *args):
        return (target(self, *args))

    return (wrapper)


class IRCClient(SocketServer.BaseRequestHandler):
    """
    IRC client connect and command handling. Client connection is handled by
    the `handle` method which sets up a two-way communication with the client.
    It then handles commands sent by the client by dispatching them to the
    handle_ methods.
    """

    def __init__(self, request, client_address, server):
        self.connected_at = str(time.time())[:10] 
        self.last_activity = 0                    # Subtract this from time.time() to determine idle time.
        self.user = None                          # The bit before the @
        self.host = client_address                # Client's hostname / ip.
        self.rhost = lookup(self.host[0])         # This users rdns. May return None.
        self.hostmask = hashlib.new('sha512',     # Unique hostmask to keep bans functioning.
                                    self.host[0]).hexdigest()[:len(self.host[0])]
        self.realname = None                      # Client's real name
        self.nick = None                          # Client's currently registered nickname
        self.vhost = None                         # Alternative hostmask for WHOIS requests
        self.send_queue = []                      # Messages to send to client (strings)
        self.channels = {}                        # Channels the client is in
        self.modes = {'x':1}                      # Usermodes set on the client
        self.oper = None                          # Assign an IRCOperator object if user opers up
        self.supported_modes = {                  # Uppercase modes are oper-only
        'A':"IRC Administrator.",
#        'b':"Bot.",
        'D':"Deaf. User does not recieve channel messages.",
        'H':"Hide ircop line in /whois.",
#        'I':"Invisible. Doesn't appear in /whois, /who, /names, doesn't appear to /join, /part or /quit",
        'N':"Network Administrator.",
        'O':"IRC Operator.",
#        'P':"Protected. Blocks users from kicking, killing, or deoping the user.",
#        'p':"Hidden Channels. Hides the channels line in the users /whois",
        'Q':"Kick Block. Cannot be /kicked from channels.",
        'S':"See Hidden Channels. Allows the IRC operator to see +p and +s channels in /list",
        'W':"Wallops. Recieve connect, disconnect and traceback notices.",
#        'X':"Whois Notification. Allows the IRC operator to see when users /whois him or her.",
        'x':"Masked hostname. Hides the users hostname or IP address from other users.",
        'Z':"SSL connection."
        }

        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        """
        The nucleus of the IRCd.
        """
        logging.info('Client connected: %s' % self.host[0])

        # TLS here. TODO: Recognise other SSL handshakes.
        if re.match(b'\x16\x03[\x00-\x03]..\x01',
                    self.request.recv(16, socket.MSG_PEEK)):
            logging.info('%s is using SSL.' % self.host[0])
            if options.ssl_cert and options.ssl_key:
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
            else:
                self.request.close()

        # Check the server isn't full.
        if len(self.server.clients) >= MAX_CLIENTS:
            self.request.send(': MAX_CLIENTS exceeded.\n')
            self.request.close()
            logging.info('Connection refused to %s: MAX_CLIENTS exceeded.' % self.client_ident())

        # Check this host isn't K:Lined.
        for line, attributes in self.server.lines['K'].items():
            if re.match(line, self.host[0]):
                self.request.send(': This host is K:Lined. Reason: %s\n' % attributes[2])
                self.request.close()
                logging.info('Connection refused to %s: K:Lined. (%s)' % (self.client_ident(), attributes[2]))

        while True:
            buf = ''
            try:
                ready_to_read, ready_to_write, in_error = select.select([self.request], [], [], 0.1)
            except:
                break

            # Write any commands to the client.
            while self.send_queue:
                msg = self.send_queue.pop(0)
                logging.debug('to %s: %s' % (self.client_ident(), msg))
                self.request.send(msg.encode('utf-8', 'ignore') + '\n')

            # See if the client has any commands for us.
            if len(ready_to_read) == 1 and ready_to_read[0] == self.request:
                try:
                    data = self.request.recv(1024)
                except Exception, e:
                    logging.error(e.message)
                    break

                if not data:
                    break
                elif len(data) > 0:
                    # There is data. Process it and turn it into line-oriented input.
                    buf += str(data)

                    while buf.find("\n") != -1:
                        line, buf = buf.split("\n", 1)
                        line = line.rstrip()

                        handler = response = ''
                        try:
                            logging.debug('from %s: %s' %
                                          (self.client_ident(), line))
                            if ' ' in line:
                                command, params = line.split(' ', 1)
                            else:
                                command = line
                                params = ''
                            # The following part checks if a command is in Scripts.commands and calls its __call__ method.
                            # This allows scripts to replace built-in commands.
                            script = self.server.scripts.commands.get(
                                command.lower())
                            if script:
                                handler = script[0]
                                response = handler(self, command, params)
                            else:
                                handler = getattr(self, 'handle_%s' % (command.lower()), None)
                                if handler: response = handler(params)
                            if not handler:
                                logging.info(
                                    'No handler for command: %s. Full line: %s' % (command, line))
                                raise IRCError(ERR_UNKNOWNCOMMAND, ':%s Unknown command' % command.upper())
                        except AttributeError, err:
                            response = ':%s ERROR :%s %s' % (SRV_DOMAIN, self.client_ident(), err)
                            self.broadcast('umode:W', response)
                            logging.error(err)
                        except IRCError, err:
                            response = ':%s %s %s %s' % (SRV_DOMAIN, err.code, self.nick, err.value)
                            logging.error('%s' % (response))
                    # It helps to comment the following exception when debugging
                        except Exception, err:                                
                            response = ':%s ERROR :%s %s' % (SRV_DOMAIN, self.client_ident(), err)
                            self.broadcast('umode:W', response)
                            self.broadcast(self.nick, response)
                            logging.error(err)
                        if response:
                            logging.debug('to %s: %s' % (self.client_ident(), response))
                            self.request.send(response + '\r\n')

                        # Handle ping timeouts.
                        if MAX_TICKS[0] >= MAX_TICKS[1]:
                            for client in self.server.clients.values():
                                then = int(client.last_activity)
                                now = int(str(time.time())[:10])
                                if (now - then) > MAX_IDLE:
                                    client.finish(response=':%s QUIT :Ping timeout. Idle %i seconds.' % \
                                        (client.client_ident(True), now - then))
                            MAX_TICKS[0] = 0
                        else:
                            MAX_TICKS[0] += 1
#        self.request.close()

#    @links
    def broadcast(self, target, message):
        """
        Handle message dispatch to clients.
        """
        if target == '*':
            [client.send_queue.append(message)
             for client in self.server.clients.values()]
        elif target.startswith('#'):
            channel = self.server.channels.get(target)
            if channel:
                [client.send_queue.append(message)
                 for client in channel.clients if not 'D' in client.modes]
        elif target.startswith('ident:'):
            rhost = re_to_irc(target.split(':')[1], False)
            [client.send_queue.append(message) for client in self.server.clients.values() \
                if re.match(rhost, c.client_ident(True))]
        elif target.startswith('umode:'):
            umodes = target.split(':')[1]
            for client in self.server.clients.values():
                if umodes in client.modes: client.send_queue.append(message)
                else:
                    for mode in umodes:
                        if mode in client.modes:
                            client.send_queue.append(message)
                            break
        elif target.startswith('cmode:'):
            cmodes = target.split(':')[1]
            for channel in self.server.channels.values():
                if cmodes in channel.modes:
                    for client in channel.clients:
                        client.send_queue.append(message)
                    break
                else:
                    for mode in cmodes:
                        if mode in channel.modes:
                            for client in channel.clients:
                                client.send_queue.append(message)
                            break
        else:
            client = self.server.clients.get(target)
            if client: client.send_queue.append(message)

    def msg(self, params):
        if self in self.server.clients.values():
            self.request.send(':%s NOTICE %s :%s\n' % (SRV_DOMAIN, self.nick, params))
        else:
            client = self.server.clients.get(self.nick)
            if client:
                client.send_queue.append(':%s NOTICE %s :%s' % (SRV_DOMAIN, self.nick, params))

    @scripts
    def handle_privmsg(self, params):
        """
        Handle sending a private message to a user or channel.
        """
        self.last_activity = str(time.time())[:10]
        if not ' ' in params:
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
                    message = ':%s PRIVMSG %s %s' % (
                        channel.supported_modes['r'].split()[0], target, msg)
                for client in channel.clients:
                    if client != self and not 'D' in client.modes:
                        self.broadcast(client.nick, message)
            else:
                raise IRCError(ERR_NOSUCHNICK, '%s' % target)
        else:
            # Message to user
            client = self.server.clients.get(target, None)
            if client: self.broadcast(client.nick, message)
            else: raise IRCError(ERR_NOSUCHNICK, '%s' % target)

    @scripts
    def handle_nick(self, params):
        """
        Handle the initial setting of the user's nickname and nick changes.
        """
        nick = params
        # Valid nickname?
        if re.search('[^a-zA-Z0-9\-\[\]\'`^{}_]',
                     nick) or len(nick) > MAX_NICKLEN:
            raise IRCError(ERR_ERRONEUSNICKNAME, ':%s' % (nick))

        # Doesn't overlap with anyone else already here?
        for i in self.server.clients.keys():
            if nick.lower() == i.lower():
                raise IRCError(ERR_NICKNAMEINUSE, 'NICK :%s' % nick)

        if not self.nick:
            # New connection
            self.nick = nick
            self.server.clients[nick] = self
            self.broadcast(self.nick, ':%s %s %s :%s' % \
                 (self.server.servername, RPL_WELCOME, self.nick, SRV_WELCOME))
            self.broadcast(self.nick, ':%s %s %s :Your host is %s, running version %s' % \
                (self.server.servername, RPL_YOURHOST, self.nick, SRV_DOMAIN, SRV_VERSION))
            self.broadcast(self.nick, ':%s %s %s :This server was created %s' % \
                (self.server.servername, RPL_CREATED, self.nick, SRV_CREATED))
            # opers, channels, clients and MOTD
            self.handle_lusers(None)
            self.handle_motd(None)
            # Hostmasking
            self.broadcast(self.nick, ':%s %s %s %s :is now your displayed host' % \
                (SRV_DOMAIN, RPL_HOSTHIDDEN, self.nick, self.hostmask))
            if self.modes:
                self.broadcast(self.nick, ':%s MODE %s +%s' % \
                    (self.client_ident(True), self.nick, ''.join(self.modes.keys())))
            self.broadcast('umode:W', ':%s NOTICE *: Client %s connected.' %
                           (SRV_DOMAIN, self.client_ident()))
        else:
            self.last_activity = str(time.time())[:10]
            if self.server.clients.get(nick, None) == self:
                # Already registered to user
                return ()
            else:
                # Nick is available. Change the nick.
                message = ':%s NICK :%s' % (self.client_ident(), nick)

                self.server.clients.pop(self.nick)
                prev_nick = self.nick
                self.nick = nick
                self.server.clients[self.nick] = self

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
                        if client != self:  # do not send to client itself.
                            self.broadcast(client.nick, message)
                # Send a notification of the nick change to the client itself
                self.broadcast(self.nick, message)

    @scripts
    def handle_user(self, params):
        """
        Handle the USER command which identifies the user to the server.
        """
        if params.count(' ') < 3:
            raise IRCError(ERR_NEEDMOREPARAMS, '%s :Not enough parameters' %
                           (USER))

        if not self.user:
            user, mode, unused, realname = params.split(' ', 3)
            self.user = user
            self.realname = realname[1:]
            for mode, script in self.server.scripts.umodes.items():
                self.supported_modes[mode] = script[1]
                script = script[0]
                try:
                    script.execute({'client': self, 'mode': mode, 'new': True})
                except Exception, err:
                    logging.error('%s in %s' % (err, script.file))
                    self.broadcast('umode:W', ':%s ERROR %s found %s in %s while connecting.' % \
                    (SRV_DOMAIN, self.client_ident(), err, script.file))
            return ('')

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

    @scripts
    def handle_motd(self, params):
        if os.path.exists('MOTD'):
            MOTD = open('MOTD')
            for line in MOTD:
                self.broadcast(self.nick, ":%s 372 %s :- %s" %
                               (SRV_DOMAIN, self.nick, line.strip('\n')))
        else:
            self.broadcast(self.nick, ":%s 372 %s :- MOTD file missing." %
                           (SRV_DOMAIN, self.nick))
        self.broadcast(self.nick, ':%s 376 %s :End of MOTD command.' %
                       (self.server.servername, self.nick))

    @scripts
    def handle_rules(self, params):
        if os.path.exists('RULES'):
            RULES = open('RULES')
            for line in RULES:
                self.broadcast(self.nick, ":%s 232 %s :- %s" %
                               (SRV_DOMAIN, self.nick, line.strip('\n')))
        else:
            self.broadcast(self.nick, ":%s 434 %s :- RULES file missing." %
                           (SRV_DOMAIN, self.nick))
        self.broadcast(self.nick, ':%s 376 %s :End of RULES command.' %
                       (self.server.servername, self.nick))

    def handle_ping(self, params):
        """
        Handle client PING requests to keep the connection alive.
        """
        self.last_activity = str(time.time())[:10]
        return (':%s PONG :%s' %
                (self.server.servername, self.server.servername))

    @scripts
    def handle_join(self, params):
        """
        Handle the JOINing of a user to a channel. Valid channel names start
        with a # and consist of a-z, A-Z, 0-9 and/or '_'.
        """
        self.last_activity = str(time.time())[:10]
        new_channel = None
        channel_names = params.split(' ', 1)[0]  # Ignore keys
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
                response = ':%s PART :%s' % (self.client_ident(True),
                                             r_channel_name)
                self.broadcast(self.nick, response)
                raise IRCError(
                    500, '%s :Cannot join channel (channel limit has been met)'
                    % r_channel_name)

            channel = self.server.channels.setdefault(
                r_channel_name, IRCChannel(r_channel_name))

            # Check the channel isn't +i
            if 'i' in channel.modes:
                if self.nick in channel.modes['i']:
                    channel.modes['i'].remove(self.nick)
                else:
                    raise IRCError(ERR_INVITEONLYCHAN, ':%s' % channel.name)

            # Check the channel isn't +OA
            if ('O' in channel.modes and not
                self.oper) or ('A' in channel.modes and not self.oper):
                raise IRCError(500, '%s :Must be an IRC operator' %
                               channel.name)

            # Channel bans and exceptions
            if not self.oper:
                if 'b' in channel.modes and 'e' in channel.modes:
                    for b in channel.modes['b']:
                        for e in channel.modes['e']:
                            if re.match(e.split()[0], self.client_ident(True)):
                                break
                        else:
                            if re.match(b.split()[0], self.client_ident(True)):
                                raise IRCError(ERR_BANNEDFROMCHAN,
                                               '%s :Cannot join channel (+b)' %
                                               channel.name)
                            continue  # executed if the loop ended normally (no break)
                        break  # executed if 'continue' was skipped (break)
                elif 'b' in channel.modes:
                    for b in channel.modes['b']:
                        if re.match(b.split()[0], self.client_ident(True)):
                            raise IRCError(ERR_BANNEDFROMCHAN,
                                           '%s :Cannot join channel (+b)' %
                                           channel.name)

            # Add scripts to supported modes and set script modes.
            if new_channel:
                channel.modes['o'].append(self.nick)
                for mode, script in self.server.scripts.cmodes.items():
                    channel.supported_modes[mode] = script[1]
                    script = script[0]
                    try:
                        script.execute({
                            'client': self,
                            'channel': channel,
                            'mode': mode,
                            'new': True
                        })
                        if 'cancel' in script.env:
                            if len(channel.clients) < 1:
                                self.server.channels.pop(channel.name)
                            if type(script['cancel']) == str:
                                return (script['cancel'])
                            else:
                                return ('')
                    except Exception, err:
                        logging.error('%s in %s' % (err, script.file))
                        self.broadcast('umode:W', ':%s ERROR %s found %s in %s while joining %s' % \
                        (SRV_DOMAIN, self.client_ident(), err, script.file, r_channel_name))

            # Add ourself to the channel and the channel to users channel list
            channel.clients.add(self)
            self.channels[channel.name] = channel

            # Send join message to everybody in the channel, including yourself
            response = ':%s JOIN :%s' % (self.client_ident(masking=True),
                                         r_channel_name)
            if ('I' in self.modes) or ('r' in channel.modes):
                self.broadcast(self.nick, response)
            else:
                self.broadcast(channel.name, response)

            # Send the topic
            if channel.topic:
                response = ':%s %s %s %s :%s' % \
                    (SRV_DOMAIN, RPL_TOPIC, self.nick, channel.name, channel.topic)
                self.broadcast(self.nick, response)
                response = ':%s %s %s %s %s %s' % \
                    (SRV_DOMAIN, RPL_TOPICWHOTIME, self.nick, channel.name, channel.topic_by, channel.topic_time)
                self.broadcast(self.nick, response)

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
                del tmp, nicks, v,h,o,a,q

    @scripts
    def handle_mode(self, params):
        """
        Handle the MODE command which sets and requests UMODEs and CMODEs
        """
        self.last_activity = str(time.time())[:10]
        #       :nick!user@host MODE (#channel) +mode (args)
        if ' ' in params:  # User is attempting to set a mode
            modeline = ''
            unknown_modes = ''
            argument = None
            target, mode = params.split(' ', 1)
            if ' ' in mode: mode, argument = mode.split(' ', 1)
            if target.startswith('#'):
                channel = self.server.channels.get(target)
                if not channel: raise IRCError(ERR_NOSUCHCHANNEL, target)
                # Retrieving bans and excepts
                if mode in ['b', '+b', 'e', '+e'] and not argument:
                    m = mode[-1]
                    if m in channel.modes:
                        for item in channel.modes[m]:
                            item = item.split()
                            item[0] = re_to_irc(item[0])
                            item = ' '.join(item)
                            if m == 'b':
                                line = ":%s %s %s %s %s" % \
                                (SRV_DOMAIN, RPL_BANLIST, self.nick, channel.name, item)
                            elif m == 'e':
                                line = ":%s %s %s %s %s" % \
                                (SRV_DOMAIN, RPL_EXCEPTLIST, self.nick, channel.name, item)
                            self.broadcast(self.nick, line)
                    if m == 'b':
                        response = ":%s %s %s %s :End of Channel Ban List" % \
                        (SRV_DOMAIN, RPL_ENDOFBANLIST, self.nick, channel.name)
                    elif m == 'e':
                        response = ":%s %s %s %s :End of Channel Exception List" % \
                        (SRV_DOMAIN, RPL_ENDOFEXCEPTLIST, self.nick, channel.name)
                    self.broadcast(self.nick, response)
                elif self.nick in channel.modes['h'] or self.nick in channel.modes['o'] \
                or self.nick in channel.modes['a'] or self.nick in channel.modes['q'] or self.oper:
                    if not argument:
                        args = []
                        if ':' in mode: mode, args = mode.split(':', 1)
                        if args:
                            args = args.split(',')  # /mode +script value value
                        if mode.startswith(
                            '+'):  # is the same as /mode +script:value,value
                            mode = mode[1:]
                            if mode in self.server.scripts.cmodes and mode in channel.supported_modes:
                                if mode.isupper() and not self.oper: return ()
                                if not mode in channel.modes:
                                    channel.modes[mode] = args
                                elif type(channel.modes[mode]) == list and args:
                                    channel.modes[mode].extend(args)
                                script = self.server.scripts.cmodes[mode][0]
                                # Send "set=True" into the scripts' namespace so it knows to adjust this channel.
                                try:
                                    script.execute({
                                        'client': self,
                                        'channel': channel,
                                        'mode': mode,
                                        'args': args,
                                        'set': True
                                    })
                                    if 'cancel' in script.env:
                                        if type(script['cancel']) == str:
                                            return (script['cancel'])
                                        else:
                                            return ('')
                                    self.broadcast(target, ":%s MODE %s %s" %
                                                   (self.client_ident(True),
                                                    target, params.split()[1]))
                                    return ()
                                except Exception, err:
                                    del channel.modes[mode]
                                    logging.error('%s in %s' %
                                                  (err, script.file))
                                    self.broadcast('umode:W', ':%s ERROR %s found %s in %s' % \
                                        (SRV_DOMAIN, self.client_ident(), err, script.file))
                            else:
                                for i in mode:
                                    if not i in channel.supported_modes:
                                        unknown_modes = unknown_modes + i
                                        continue
                                    if i.isupper() and not self.oper: continue
                                    if i not in channel.modes:
                                        channel.modes[i] = args
                                        modeline = modeline + i
                            if modeline:
                                message = ":%s MODE %s +%s" % (
                                    self.client_ident(True), target, modeline)
                                self.broadcast(target, message)
                            if unknown_modes:
                                self.broadcast(self.nick, ':%s %s %s %s :unkown mode(s)' % \
                                    (SRV_DOMAIN, ERR_UNKNOWNMODE, self.nick, unknown_modes))
                        elif mode.startswith('-'):
                            mode = mode[1:]
                            removed_args = []
                            if mode in self.server.scripts.cmodes and mode in channel.modes:
                                if mode.isupper() and not self.oper: return ()
                                if type(channel.modes[mode]) == list and args:
                                    for arg in args:
                                        if arg in channel.modes[mode]:
                                            channel.modes[mode].remove(arg)
                                            removed_args.append(arg)
                                script = self.server.scripts.cmodes[mode][0]
                                try:
                                    script.execute({
                                        'client': self,
                                        'channel': channel,
                                        'mode': mode,
                                        'args': args,
                                        'set': False
                                    })
                                    if 'cancel' in script.env:
                                        if type(script['cancel']) == str:
                                            return (script['cancel'])
                                        else:
                                            return ('')
                                except Exception, err:
                                    logging.error('%s in %s' %
                                                  (err, script.file))
                                    self.broadcast('umode:W', ':%s ERROR %s found %s in %s' % \
                                        (SRV_DOMAIN, self.client_ident(), err, script.file))
                                if mode in channel.modes:
                                    # Using "/mode -script:" clears all values.
                                    if type(args) == str:
                                        del channel.modes[mode]
                                        # Here we try to unset the mode if sending "set=False" into the
                                        # script hasn't caused it to extricate its effects from the channel.
                                    elif type(channel.modes[mode]) == int:
                                        del channel.modes[mode]
                                    else:
                                        try:
                                            if len(channel.modes[mode]) == 0:
                                                del channel.modes[mode]
                                        except:
                                            pass  # TODO: Craft a scenario where this pass is met, and return output to users about it.
                                if removed_args:
                                    modeline = '%s:%s' % (
                                        mode, ','.join(removed_args))
                                else:
                                    modeline = mode
                            else:
                                for i in mode:
                                    if i in channel.modes:
                                        if i.isupper() and not self.oper:
                                            continue
                                        if i in ['v', 'h', 'o', 'a', 'q', 'e',
                                                 'b']:
                                            continue
                                        if i == 'i' or (
                                            type(channel.modes[i]) == int
                                        ) or (len(channel.modes[i]) == 0):
                                            del channel.modes[i]
                                        modeline = modeline + i
                            if mode in channel.modes:
                                if type(channel.modes[mode]) == list:
                                    self.msg('%s +%s contains \x02%s\x0F.' %
                                             (channel.name, mode,
                                              '\x0F, \x02'.join(
                                                  channel.modes[mode])))
                                self.msg(
                                    'Use \x02\x1F/MODE %s -%s:\x0F to clear.' %
                                    (channel.name, mode))
                            elif modeline:
                                message = ":%s MODE %s -%s" % (
                                    self.client_ident(True), target, modeline)
                                self.broadcast(target, message)

                    else:  # A mode with arguments. Chan ops, bans, excepts..
                        args = argument.split(' ')
                        if mode.startswith('+'):
                            mode = mode[1:]
                            if mode in self.server.scripts.cmodes and mode in channel.supported_modes:
                                if mode.isupper() and not self.oper: return ()
                                if not mode in channel.modes:
                                    channel.modes[mode] = args
                                elif type(channel.modes[mode]) == list and args:
                                    channel.modes[mode].extend(args)
                                script = self.server.scripts.cmodes[mode][0]
                                try:
                                    script.execute({
                                        'client': self,
                                        'channel': channel,
                                        'mode': mode,
                                        'args': args,
                                        'set': True
                                    })
                                    if 'cancel' in script.env:
                                        if type(script['cancel']) == str:
                                            return (script['cancel'])
                                        else:
                                            return ('')
                                    modeline = mode
                                except Exception, err:
                                    del channel.modes[mode]
                                    logging.error('%s in %s' %
                                                  (err, script.file))
                                    self.broadcast('umode:W', ':%s ERROR %s found %s in %s' % \
                                    (SRV_DOMAIN, self.client_ident(), err, script.file))
                            else:
                                for i in mode:
                                    if not i in channel.supported_modes:
                                        unknown_modes += i
                                        continue
                                    for n in args:
                                        if (i == 'v' or i == 'h' or i == 'o' or
                                            i == 'a' or i == 'q') and (
                                                i in channel.supported_modes):
                                            if not i in channel.modes:
                                                channel.modes[i] = []
                                            if not self.oper:
                                                if (i == 'a' or i == 'q'
                                                    ) and (not self.nick in
                                                           channel.modes['q']):
                                                    raise IRCError(
                                                        ERR_CHANOWNPRIVNEEDED,
                                                        "%s You're not a channel owner."
                                                        % channel.name)
                                                if (i == 'o') and (not self.nick in channel.modes['o'] and not self.nick in channel.modes['a'] \
                                                and not self.nick in channel.modes['q']):
                                                    raise IRCError(
                                                        ERR_NOTFORHALFOPS,
                                                        "Halfops cannot set mode %s"
                                                        % i)
                                            if n not in channel.modes[i]:
                                                channel.modes[i].append(n)
                                                modeline += i
                                                args.remove(n)
                                        elif (
                                            i == 'b' or i == 'e'
                                        ) and i in channel.supported_modes:
                                            n = re_to_irc(n, False)
                                            if not i in channel.modes:
                                                channel.modes[i] = []
                                            channel.modes[i].append(
                                                '%s %s %s' %
                                                (n, self.nick,
                                                 str(time.time())[:10]))
                                            modeline += i
                            if modeline:
                                message = ":%s MODE %s +%s %s" % (
                                    self.client_ident(True), target, modeline,
                                    argument)
                                self.broadcast(target, message)
                            if unknown_modes:
                                self.broadcast(self.nick, ':%s %s %s %s :unkown mode(s)' % \
                                (SRV_DOMAIN, ERR_UNKNOWNMODE, self.nick, unknown_modes))
                        elif mode.startswith('-'):
                            mode = mode[1:]
                            removed_args = []
                            if mode in self.server.scripts.cmodes and mode in channel.modes:
                                if mode.isupper() and not self.oper: return ()
                                if type(channel.modes[mode]) == list and args:
                                    for arg in args:
                                        if arg in channel.modes[mode]:
                                            channel.modes[mode].remove(arg)
                                            removed_args.append(arg)
                                script = self.server.scripts.cmodes[mode][0]
                                try:
                                    script.execute({
                                        'client': self,
                                        'channel': channel,
                                        'mode': mode,
                                        'args': args,
                                        'set': False
                                    })
                                    if 'cancel' in script.env:
                                        if type(script['cancel']) == str:
                                            return (script['cancel'])
                                        else:
                                            return ('')
                                except Exception, err:
                                    logging.error('%s in %s' %
                                                  (err, script.file))
                                    self.broadcast('umode:W', ':%s ERROR %s found %s in %s' % \
                                    (SRV_DOMAIN, self.client_ident(), err, script.file))
                                if mode in channel.modes:
                                    if type(channel.modes[mode]) == int:
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
                                        if (i == 'v' or i == 'h' or i == 'o' or
                                            i == 'a' or i ==
                                            'q') and (i in channel.modes):
                                            if not self.oper:
                                                if (i == 'a' or i == 'q'
                                                    ) and (not self.nick in
                                                           channel.modes['q']):
                                                    raise IRCError(
                                                        ERR_CHANOWNPRIVNEEDED,
                                                        "%s You're not a channel owner."
                                                        % channel.name)
                                                if (i == 'o') and (not self.nick in channel.modes['o'] and not self.nick in channel.modes['a'] \
                                                and not self.nick in channel.modes['q']):
                                                    raise IRCError(
                                                        ERR_NOTFORHALFOPS,
                                                        "Halfops cannot unset mode %s"
                                                        % i)
                                            if n in channel.modes[i]:
                                                channel.modes[i].remove(n)
                                                modeline += i
                                                args.remove(n)
                                        elif (i == 'b' or i ==
                                              'e') and i in channel.modes:
                                            n = re_to_irc(n, False)
                                            for entry in channel.modes[i]:
                                                if entry.split()[0] == n:
                                                    channel.modes[i].remove(entry)
                                                    modeline += i
                                        elif i == 'i':
                                            del channel.modes[i]
                                            modeline += i
                            if modeline:
                                message = ":%s MODE %s -%s %s" % (
                                    self.client_ident(True), target, modeline,
                                    argument)
                                self.broadcast(target, message)
                else:
                    raise IRCError(ERR_CHANOPPRIVSNEEDED,
                                   '%s You are not a channel operator.' %
                                   channel.name)

            else:  # User modes.
                if (self.nick == target) or self.oper:
                    user = self.server.clients.get(target)
                    if not user: raise IRCError(ERR_NOSUCHNICK, target)
                    modeline = ''
                    if mode.startswith('+'):
                        for i in mode[1:]:
                            if i in self.supported_modes and i not in self.modes:
                                if i.isupper() and not self.oper: continue
                                user.modes[i] = 1
                                modeline = modeline + i
                        if len(modeline) > 0:
                            response = ':%s MODE %s +%s' % (
                                self.client_ident(True), user.nick, modeline)
                            self.broadcast(self.nick, response)
                            if user.nick != self.nick:
                                self.broadcast(user.nick, response)
                    elif mode.startswith('-'):
                        for i in mode[1:]:
                            if i in user.modes:
                                if i.isupper() and not self.oper: continue
                                del user.modes[i]
                                modeline = modeline + i
                        if len(modeline) > 0:
                            response = ':%s MODE %s -%s' % (
                                self.client_ident(True), user.nick, modeline)
                            self.broadcast(self.nick, response)
                            if user.nick != self.nick:
                                self.broadcast(user.nick, response)

        else:  # User is requesting a list of modes
            if params.startswith('#'):
                modes = ''
                scripts = []
                channel = self.server.channels.get(params)
                if not channel:
                    raise IRCError(ERR_NOSUCHCHANNEL, '%s :%s' %
                                   (params, params))
                if not self.oper and self not in channel.clients:
                    raise IRCError(ERR_NOTONCHANNEL,
                                   '%s :%s You are not in that channel.' %
                                   (channel.name, channel.name))
                for mode in channel.modes:
                    if mode in ['v', 'h', 'o', 'a', 'q', 'e', 'b']: continue
                    if mode in self.server.scripts.cmodes:
                        ns = {
                            'client': self,
                            'channel': channel,
                            'mode': mode,
                            'display': True
                        }
                        script = self.server.scripts.cmodes[mode][0]
                        try:
                            # Using "item" to avoid race conditions.
                            item = script.execute(ns)
                            if 'output' in item:
                                scripts.append('%s %s' %
                                               (mode, item['output']))
                            else:
                                scripts.append(mode)
                        except Exception, err:
                            logging.error('%s in %s' % (err, script.file))
                            self.broadcast('umode:W', ':%s ERROR %s found %s in %s' % \
                                (SRV_DOMAIN, self.client_ident(), err, script.file))
                    if len(mode) == 1: modes = modes + mode
                self.broadcast(self.nick, ':%s 324 %s %s +%s' %
                               (self.server.servername, self.nick, params,
                                modes))
                for item in scripts:
                    self.broadcast(self.nick, ':%s 324 %s %s +%s' % \
                    (SRV_DOMAIN, self.nick, params, item))
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
                                scripts.apppend('%s %s' %
                                                (mode, item['output']))
                            else:
                                scripts.append(mode)
                            scripts.append(item)
                        except Exception, err:
                            logging.error('%s in %s' % (err, script.file))
                            self.broadcast('umode:W', ':%s ERROR %s found %s in %s' % \
                                (SRV_DOMAIN, self.client_ident(), err, script.file))
                    if len(mode) == 1: modes = modes + mode
                self.broadcast(self.nick, ':%s %s %s :%s' %
                               (SRV_DOMAIN, RPL_UMODEIS, params, modes))
                for item in scripts:
                    self.broadcast(self.nick, ':%s %s %s %s +%s' % \
                    (SRV_DOMAIN, RPL_UMODEIS, params, item))

    @scripts
    def handle_invite(self, params):
        """
        Handle the invite command.
        """
        self.last_activity = str(time.time())[:10]
        target, channel = params.strip(':').split(' ', 1)
        channel = self.server.channels.get(channel)
        if channel and 'i' in channel.modes and target in self.server.clients:
            if self.nick in channel.modes['h'] or self.nick in channel.modes['o'] \
            or self.nick in channel.modes['a'] or self.nick in channel.modes['q'] or self.oper:
                channel.modes['i'].append(target)

                response = ':%s %s %s %s %s' % \
                    (SRV_DOMAIN, RPL_INVITING, self.nick, target, channel.name)
                self.broadcast(self.nick, response)

                # Tell the channel
                response = ':%s NOTICE @%s :%s invited %s into the channel.' % \
                    (SRV_DOMAIN, channel.name, self.nick, target)
                self.broadcast(channel.name, response)

                # Tell the invitee
                response = ':%s INVITE %s :%s' % \
                    (self.client_ident(True), target, channel.name)
                self.broadcast(target, response)
            else:
                raise IRCError(ERR_CHANOPPRIVSNEEDED, '%s :%s You are not a channel operator.' % \
                    (channel.name, channel.name))

    @scripts
    def handle_knock(self, params):
        self.last_activity = str(time.time())[:10]
        channel = self.server.channels.get(params)
        if channel:
            if 'i' in channel.modes and not channel.name in self.channels:
                response = ':%s NOTICE @%s :%s knocked on %s.' % \
                    (SRV_DOMAIN, channel.name, self.nick, channel.name)
                self.broadcast(channel.name, response)
                response = ':%s NOTICE %s : Knocked on %s' % \
                    (SRV_DOMAIN, self.nick, channel.name)
                self.broadcast(self.nick, response)

    @scripts
    def handle_whois(self, params):
        """
        Handle the whois command.
        """
        self.last_activity = str(time.time())[:10]
        # TODO: IP Addr, Admin, Oper, Bot lines.
        user = self.server.clients.get(params)
        if user:
            # Userhost line.
            if user.vhost:
                response = ':%s %s %s %s %s %s * %s' % \
                    (SRV_DOMAIN, RPL_WHOISUSER, self.nick, user.nick, user.nick, user.vhost, user.realname)
                self.broadcast(self.nick, response)
            else:
                response = ':%s %s %s %s %s %s * %s' % \
                    (SRV_DOMAIN, RPL_WHOISUSER, self.nick, user.nick, user.nick, user.hostmask, user.realname)
                self.broadcast(self.nick, response)

            # Channels the user is in. Modify to show op status.
            channels = []
            for channel in user.channels.values():
                if 'p' not in channel.modes: channels.append(channel.name)
            if channels:
                response = ':%s %s %s %s :%s' % \
                    (SRV_DOMAIN, RPL_WHOISCHANNELS, self.nick, user.nick, ' '.join(channels))
                self.broadcast(self.nick, response)

            # Oper info
            if user.oper and 'H' not in user.modes:
                if 'A' in user.modes:
                    response = ':%s %s %s %s :%s is a server admin.' % \
                        (SRV_DOMAIN, RPL_WHOISOPERATOR, self.nick, user.nick, user.nick)
                    self.broadcast(self.nick, response)
                if 'O' in user.modes:
                    response = ':%s %s %s %s :%s is a server operator.' % \
                        (SRV_DOMAIN, RPL_WHOISOPERATOR, self.nick, user.nick, user.nick)
                    self.broadcast(self.nick, response)

            if self.oper or self.nick == user.nick:
                if user.rhost:
                    response = ':%s %s %s %s %s %s' % \
                        (SRV_DOMAIN, RPL_WHOISSPECIAL, self.nick, user.nick, user.rhost, user.host[0])
                    self.broadcast(self.nick, response)
                else:
                    response = ':%s %s %s %s %s' % \
                        (SRV_DOMAIN, RPL_WHOISSPECIAL, self.nick, user.nick, user.host[0])
                    self.broadcast(self.nick, response)

            # Server info line
            response = ':%s %s %s %s %s :%s' % \
                (SRV_DOMAIN, RPL_WHOISSERVER, self.nick, user.nick, SRV_DOMAIN, SRV_DESCRIPTION)
            self.broadcast(self.nick, response)

            if 'Z' in user.modes:
                response = ':%s %s %s %s :is using a secure connnection' % \
                    (SRV_DOMAIN, RPL_WHOISSECURE, self.nick, user.nick)
                self.broadcast(self.nick, response)

            # Idle and connection time.
            idle_time = int(str(time.time())[:10]) - int(user.last_activity)
            response = ':%s %s %s %s %i %s :seconds idle, signon time' % \
                (SRV_DOMAIN, RPL_WHOISIDLE, self.nick, user.nick, idle_time, user.connected_at)
            self.broadcast(self.nick, response)

            # That about wraps 'er up.
            response = ':%s %s %s %s :End of /WHOIS list.' % (
                SRV_DOMAIN, RPL_ENDOFWHOIS, self.nick, user.nick)
        else:
            raise IRCError(ERR_UNKNOWNCOMMAND, '%s is a cool guy.' %
                           params.split(' ', 1)[0])

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
                        (SRV_DOMAIN, RPL_WHOREPLY, self.nick, channel.name, client.user, host, SRV_DOMAIN, client.nick, client.realname))
                    else:
                        self.broadcast(self.nick, ":%s %s %s %s %s %s %s %s H :n/a %s" % \
                        (SRV_DOMAIN, RPL_WHOREPLY, self.nick, channel.name, client.user, host, SRV_DOMAIN, client.nick, client.realname))
                self.broadcast(self.nick, ":%s %s %s %s :End of /WHO list." %
                               (SRV_DOMAIN, RPL_ENDOFWHO, self.nick,
                                channel.name))
        elif self.oper and params == '*':
            for client in self.server.clients.values():
                host = client.client_ident(True)
                host = host.split('@')[1]
                if client.oper:
                    self.broadcast(self.nick, ":%s %s %s - %s %s %s %s H* :n/a %s" % \
                    (SRV_DOMAIN, RPL_WHOREPLY, self.nick, client.user, host, SRV_DOMAIN, client.nick, client.realname))
                else:
                    self.broadcast(self.nick, ":%s %s %s %s %s %s %s H :n/a %s" % \
                    (SRV_DOMAIN, RPL_WHOREPLY, self.nick, client.user, host, SRV_DOMAIN, client.nick, client.realname))
            self.broadcast(self.nick, ":%s %s %s %s :End of /WHO list." %
                           (SRV_DOMAIN, RPL_ENDOFWHO, self.nick, client.nick))
        else:
            client = self.server.clients.get(params)
            if not client: raise IRCError(ERR_NOSUCHNICK, params)
            else:
                host = client.client_ident(True)
                host = host.split('@')[1]
                if client.oper:
                    self.broadcast(self.nick, ":%s %s %s - %s %s %s %s H* :n/a %s" % \
                    (SRV_DOMAIN, RPL_WHOREPLY, self.nick, client.user, host, SRV_DOMAIN, client.nick, client.realname))
                else:
                    self.broadcast(self.nick, ":%s %s %s %s %s %s %s H :n/a %s" % \
                    (SRV_DOMAIN, RPL_WHOREPLY, self.nick, client.user, host, SRV_DOMAIN, client.nick, client.realname))
                self.broadcast(self.nick, ":%s %s %s %s :End of /WHO list." %
                               (SRV_DOMAIN, RPL_ENDOFWHO, self.nick,
                                client.nick))

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
            raise IRCError(ERR_CANNOTSENDTOCHAN, '%s :Cannot send to channel' % \
                           (channel.name))
        if topic:
            if self.nick in channel.modes['h'] or self.nick in channel.modes['o'] \
            or self.nick in channel.modes['a'] or self.nick in channel.modes['q'] or self.oper:
                if topic == channel.topic: return ()
                channel.topic = topic
                channel.topic_by = self.nick
                channel.topic_time = str(time.time())[:10]
                message = ':%s TOPIC %s :%s' % (self.client_ident(),
                                                channel_name, channel.topic)
                self.broadcast(channel.name, message)
            else:
                raise IRCError(ERR_CHANOPPRIVSNEEDED, '%s :%s You are not a channel operator.' % \
                    (channel.name, channel.name))
        else:
            self.broadcast(self.nick, ':%s %s %s %s :%s' % \
                (SRV_DOMAIN, RPL_TOPIC, self.nick, channel.name, channel.topic))
            self.broadcast(self.nick, ':%s %s %s %s %s %s' % \
                (SRV_DOMAIN, RPL_TOPICWHOTIME, self.nick, channel.name, channel.topic_by, channel.topic_time))

    @scripts
    def handle_part(self, params):
        """
        Handle a client parting from channel(s).
        """
        self.last_activity = str(time.time())[:10]
        for pchannel in params.split(','):
            if pchannel.strip() in self.channels:
                # Send message to all clients in all channels user is in, and remove the user from the channels.
                channel = self.server.channels.get(pchannel.strip())
                if ('r' not in channel.modes) or (len(channel.clients) == 1):
                    response = ':%s PART :%s' % (self.client_ident(True), pchannel)
                    self.broadcast(channel.name, response)
                self.channels.pop(pchannel)
                channel.clients.remove(self)
                if len(channel.clients) < 1:
                    self.server.channels.pop(channel.name)
                else:
                    for op_list in channel.ops:
                        if self.nick in op_list: op_list.remove(self.nick)
            else:
                response = ':%s 403 %s :%s' % (self.server.servername, pchannel, pchannel)
                self.broadcast(self.nick, response)

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
        channel, target = params.split(' ', 1)
        if ':' in target: target, message = target.split(' :', 1)

        channel = self.server.channels.get(channel)
        if not channel:
            return (':%s NOTICE %s :No such channel.' %
                    (SRV_DOMAIN, self.nick))

        if not self.oper and self.nick not in channel.modes['h'] and self.nick not in channel.modes['o'] \
        and self.nick not in channel.modes['a'] and self.nick not in channel.modes['q']:
            return (':%s %s %s %s :You are not a channel operator.' %
                    (SRV_DOMAIN, ERR_CHANOPPRIVSNEEDED, self.nick,
                     channel.name))

        target = self.server.clients.get(target)
        if not target:
            raise IRCError(ERR_NOSUCHNICK, target)

            return (':%s NOTICE @%s :No such nick.' %
                    (SRV_DOMAIN, channel.name))
        if 'Q' in target.modes:
            return (':%s NOTICE @%s :Cannot kick +Q user %s.' %
                    (SRV_DOMAIN, channel.name, target.nick))

        if not self.oper:
            if not self.nick in channel.modes['q'] and target.nick in channel.modes['q']:
                return (":%s %s %s %s :Can't kick %s." %
                        (SRV_DOMAIN, ERR_CHANOPPRIVSNEEDED, self.nick,
                         channel.name, target.nick))
            if (not self.nick in channel.modes['a'] and not self.nick in channel.modes['q']) and (target.nick in channel.modes['a'] \
            or target.nick in channel.modes['q']):
                return (":%s %s %s %s :Can't kick %s." %
                        (SRV_DOMAIN, ERR_CHANOPPRIVSNEEDED, self.nick,
                         channel.name, target.nick))
            if (not self.nick in channel.modes['o'] and not self.nick in channel.modes['a'] and not self.nick in channel.modes['q']) \
            and (target.nick in channel.modes['o'] or target.nick in channel.modes['a'] or target.nick in channel.modes['q']):
                return (":%s %s %s %s :Can't kick %s." %
                        (SRV_DOMAIN, ERR_CHANOPPRIVSNEEDED, self.nick,
                         channel.name, target.nick))

        if message:
            response = ':%s KICK %s %s :%s' % (
                self.client_ident(True), channel.name, target.nick, message)
        else:
            response = ':%s KICK %s %s :%s' % (
                self.client_ident(True), channel.name, target.nick, self.nick)

        for op_list in channel.ops:
            if target.nick in op_list: op_list.remove(target.nick)
        self.broadcast(channel.name, response)
        target.channels.pop(channel.name)
        channel.clients.remove(target)

    @scripts
    def handle_list(self, params):
        """
        Implements the /list command
        """
        self.last_activity = str(time.time())[:10]
        self.broadcast(self.nick, ':%s %s %s Channel :Users  Name' %
                       (SRV_DOMAIN, RPL_LISTSTART, self.nick))
        for channel in self.server.channels.values():
            if ('s' not in channel.modes) or ('S' in self.modes):
                tmp_modes = []
                for mode in channel.modes:
                    if mode not in ['v', 'h', 'o', 'a', 'q', 'e', 'b']:
                        tmp_modes.append(mode)
                self.broadcast(self.nick, ':%s %s %s %s %i :[+%s] %s' % \
                (SRV_DOMAIN, RPL_LIST, self.nick, channel.name, len(channel.clients), ''.join(tmp_modes), channel.topic))
        return (':%s %s %s :End of /LIST' %
                (SRV_DOMAIN, RPL_LISTEND, self.nick))

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
                password = hashlib.sha512(password).hexdigest()
                if password == OPER_PASSWORD and opername == OPER_USERNAME:
                    oper = self.server.opers.setdefault(self.nick, IRCOperator(self))
                    self.modes['A'] = 1
                    modeline = modeline + 'A'
                else:
                    oper = self.server.opers.get(opername)
                    if (not oper) or (not oper.passwd) or (oper.passwd != password):
                        return (':%s NOTICE %s :No O:Lines for your host.' %
                                (SRV_DOMAIN, self.nick))
                self.vhost = oper.vhost
                self.oper = oper
                self.broadcast('umode:W',
                               ':%s NOTICE _ :%s is now an IRC operator.' %
                               (SRV_DOMAIN, self.nick))
                for i in oper.modes:
                    self.modes[i] = 1
                    modeline = modeline + i
                self.broadcast(self.nick, ':%s MODE %s +%s' %
                               (SRV_DOMAIN, self.nick, modeline))
                return (':%s NOTICE %s :Auth successful for %s.' %
                        (SRV_DOMAIN, self.nick, opername))
            else:
                return (': Incorrect usage.')

    @scripts
    def handle_operserv(self, params):
        """
        Pass authenticated ircop commands to the IRCOperator dispatcher.
        """
        if self.oper:
            return (self.oper.dispatch(params))
        else:
            return (': OPERSERV is only available to authenticated IRCops.')

    @scripts
    def handle_chghost(self, params):
        if self.oper:
            target, vhost = params.split(' ', 1)
            target = self.server.clients.get(target)
            if target:
                target.vhost = vhost
                return (':%s NOTICE %s :Changed the vhost for %s to %s.' %
                        (SRV_DOMAIN, self.nick, target.nick, target.vhost))
            else:
                return (':%s NOTICE %s :Invalid nick: %s.' %
                        (SRV_DOMAIN, self.nick, target))
        else:
            return (
                ':%s NOTICE %s :You must be identified as an operator to use CHGHOST.'
                % (SRV_DOMAIN, self.nick))

    @scripts
    def handle_kill(self, params):
        nick, reason = params.split(' ', 1)
        reason = reason.lstrip(':')
        if self.oper:
            client = self.server.clients.get(nick)
            if client:
                if 'A' in client.modes:
                    return (':%s ERROR %s is an IRC Administrator.' %
                            (SRV_DOMAIN, client.nick))
                else:
                    client.finish(':%s QUIT :Killed by %s: %s' %
                                  (client.client_ident(True), self.nick,
                                   reason))

    @scripts
    def handle_helpop(self, params):
        """
        The helpop system provides help on commands and modes.
        Use "/helpop command commandname" for documentation on a given command.
        Use "/helpop cmode modename" for documentation on a given channel mode.
        Use "/helpop umode modename" for documentation on a given user mode.
        """
        if not ' ' in params:
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
                    message = ": %s help on user mode %s" % (SRV_DOMAIN, topic)
                    self.broadcast(self.nick, message)
                    message = ": %s" % self.supported_modes[topic]
                    self.broadcast(self.nick, message)
            elif section == "command":
                if hasattr(self, "handle_" + topic):
                    message = ": %s help on command %s" % (SRV_DOMAIN,
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
                            SRV_DOMAIN, topic.upper())
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
                    return (': There are no K:Lines defined on this server.')
                data = []
                for kline, attributes in self.server.lines['K'].items():
                    t = int(attributes[1])
                    tmp = {}
                    tmp['Operator'] = attributes[0]
                    tmp['Host'] = re_to_irc(kline)
                    tmp['Time'] = '%s (%s)' % (time.ctime(t),
                                               tconv(time.time() - t) + ' ago')
                    tmp['Reason'] = attributes[2]
                    data.append(tmp)
                fmt = format(data)
                table = tabulate(fmt, ul='-')(data)
                for line in table.split('\n'):
                    self.msg(line)
                del data, fmt, table, t, tmp
                return ()
            cmd = params.split()[0]
            if cmd.lower() == 'add':
                if len(params.split()) < 3:
                    raise IRCError(ERR_NEEDMOREPARAMS,
                                   "You must also supply a reason.")
                t = str(time.time())[:10]
                host, reason = params.split(' ', 2)[1:]
                host = re_to_irc(host, False)
                if host in self.server.lines['K']:
                    raise IRCError(500, "Host already K:Lined.")
                self.server.lines['K'][host] = [self.client_ident(True), t,
                                                reason]
                self.broadcast('umode:W',
                               ':%s NOTICE * :%s added a K:Line for %s "%s"' %
                               (SRV_DOMAIN, self.client_ident(True),
                                re_to_irc(host), reason))

            elif cmd.lower() == 'remove':
                if not ' ' in params:
                    raise IRCError(ERR_NEDMOREPARAMS,
                                   "You didn't specify which K:Line to remove.")
                host = re_to_irc(params.split()[1], False)
                if host in self.server.lines['K']:
                    del self.server.lines['K'][host]
                self.broadcast(
                    'umode:W', ':%s NOTICE * :%s removed the K:Line for %s' %
                    (SRV_DOMAIN, self.client_ident(True), params.split()[1]))

    @scripts
    def handle_sajoin(self, params):
        """
        Permits an IRC Operator to force a client to JOIN a channel.
        """
        if self.oper:
            target, channel = params.split()
            victim = self.server.clients.get(target)
            if victim: victim.handle_join(channel)

    @scripts
    def handle_sapart(self, params):
        """
        Permits an IRC Operator to force a client to PART a channel.
        """
        if self.oper:
            target, channel = params.split()
            victim = self.server.clients.get(target)
            if victim: victim.handle_part(channel)

    @scripts
    def handle_sjoin(self, params):
        """
        Join the user into a randomly named channel with modes +iarpstn.
        Doesn't show up in /list. /names returns [redacted]. PRIVMSG filters names to [redacted]
        """
        pass

    def client_ident(self, masking=None):
        """
        Return the client identifier as included in many command replies.
        """
        if masking:
            if self.vhost == None:
                return ('%s!%s@%s' % (self.nick, self.user, self.hostmask))
            else:
                return ('%s!%s@%s' % (self.nick, self.user, self.vhost))
        else:
            return ('%s!%s@%s' % (self.nick, self.user, self.host[0]))

    @scripts
    def finish(self, response=None):
        """
        The client conection is finished. Do some cleanup to ensure that the
        client doesn't linger around in any channel or the client list, in case
        the client didn't properly close the connection with PART and QUIT.
        """
        if not self.nick: return ()
        if not response:
            response = ':%s QUIT :EOF from client' % (self.client_ident(True))
        if not self.nick in self.server.clients: return ()
        #        self.request.send(response)
        peers = []
        for channel in self.channels.values():
            if self in channel.clients: channel.clients.remove(self)
            if len(channel.clients) < 1 and channel.name in self.server.channels:
                self.server.channels.pop(channel.name)
            else:
                for op_list in channel.ops:
                    if self.nick in op_list: op_list.remove(self.nick)
                for p in channel.clients:
                    peers.append(p)
        peers = set(peers)
        for peer in peers:
            self.broadcast(peer.nick, response)
        try:
            self.server.clients.pop(self.nick)
        except KeyError:
            return ()
        self.broadcast('umode:W', ':%s NOTICE *: Client %s disconnected.' %
                       (SRV_DOMAIN, self.client_ident()))
        logging.info('Client disconnected: %s' % (self.client_ident()))
        if len(self.server.clients) == 0:
            logging.info('There goes the last client.')
        self.request.close()

    def __repr__(self):
        """
        Return a user-readable description of the client
        """
        return ('<%s %s!%s@%s (%s) at %s>' %
                (self.__class__.__name__, self.nick, self.user, self.host[0],
                 self.realname, hex(id(self))))

class IRCServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        self.servername = SRV_DOMAIN
        self.channels = {}       # Existing channels (IRCChannel instances) by channel name
        self.clients = {}        # Connected clients (IRCClient instances) by nickname
        self.opers = {}          # Authenticated IRCops (IRCOperator instances) by nickname
        self.scripts = Scripts() # The scripts object we attach external execution routines to.
        self.link_key = None     # Oper-defined pass for accepting connections as server links.
        self.links = {}          # Other servers (IRCServerLink instances) in the form
                                 # {"domain_name": [shared_object, running_thread]}
        self.lines = {           # Bans we check on client connect, against...
                      'K':{},    # A userhost, locally
#                      'G':{},    # A userhost, network-wide
                      'Z':{},    # An IP range, locally
#                      'GZ':{}    # An IP range, network-wide 
                     }           # An example of the syntax is: lines['K']['*!*@*.fr]['n!u@h', '02343240', 'Reason']
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)
        self.scripts.server = self

class Shared(object):
    """
    This is a nifty shared-memory container for server links.
    """
    objects = {}
    queue   = []

class IRCServerLink(object):
    """
    Represents a connection to a remote Psyrcd instance.
    We start IRCServerLink.connect in a thread and can reasonably expect
    self.shared to be a dictionary that was created by the main thread.
    This permits inter-thread communication based on the actor model.
    """
    socket = None
    connected = False
    shared = None
    server = None

    def __init__(self, host, key):
        self.host = host
        self.key = key

    def connect(self):
        self.socket.connect(self.host)
        self.send("LINK %s %s" % (SRV_DOMAIN, self.key))

        while True:
            self.receive()
            buf = self.socket.recv(4096)
            lines = buf.split("\n")
            for data in lines:
                data = str(data).strip()
                if data == '':
                    continue
                print "I<", data

                # server ping/pong?
                if data.find('PING') != -1:
                    n = data.split(':')[1]
                    self.send('PONG :' + n)
                    if self.connected == False:
                        self.perform()
                        self.connected = True

                args = data.split(None, 3)
                if len(args) != 4:
                    continue
                ctx = {}
                ctx['sender'] = args[0][1:]
                ctx['type']   = args[1]
                ctx['target'] = args[2]
                ctx['msg']  = args[3][1:]

    def receive(self, message=None):
        """
        Receive commands from the local server, such as privmsg, whois etc.
        """
        if not message:
            message = self.shared.inbox
        func = getattr(self, "handle_" + message[0])
        func(message[1])        

class Script(object):
    """
    Represents the execution environment for a third-party script.
    We send custom values into the environment and work with whatever's left.
    Scripts can also call any methods on objects put in their environment.
    It's quite unrestricted, we trust you know what you're doing even if it's insane.
    """
    def __init__(self, file=None, env={}):
        self.read_on_exec = options.debug
        self.file = file
        self.env = env
        self.script = ''
        self.code = None
        self.hash = None
        self.cache = {
            'config': {
                'options': options,
                'logging': logging,
                'NET_NAME': NET_NAME,
                'SRV_VERSION': SRV_VERSION,
                'SRV_DOMAIN': SRV_DOMAIN,
                'SRV_DESCRIPTION': SRV_DESCRIPTION,
                'SRV_WELCOME': SRV_WELCOME,
                'MAX_NICKLEN': MAX_NICKLEN,
                'MAX_CHANNELS': MAX_CHANNELS,
                'MAX_TOPICLEN': MAX_TOPICLEN,
                'SRV_CREATED': SRV_CREATED,
                'MAX_CLIENTS': MAX_CLIENTS,
                'MAX_IDLE': MAX_IDLE
            }
        }

    def execute(self, env={}):
        if not self.code or self.read_on_exec: self.compile()
        if env: self.env = env
        self.env['cache'] = self.cache
        exec self.code in self.env
        del self.env['__builtins__']
        if 'cache' in self.env.keys():
            self.cache = self.env['cache']
        return (self.env)

    def compile(self, script=''):
        if self.file:
            f = file(self.file, 'r')
            self.script = f.read()
            f.close()
        elif script:
            self.script = script
        if self.script:
            hash = sha1sum(self.script)
            if self.hash != hash:
                self.hash = hash
                self.code = compile(self.script, '<string>', 'exec')
            self.script = ''

    def __getitem__(self, key):
        if key in self.env.keys():
            return (self.env[key])
        else:
            raise (KeyError(key))

    def __call__(self, client, command, params):
        try:
            self.execute(
                {'params': params,
                 'command': command,
                 'client': client})
            if 'output' in self.env.keys(): return (self['output'])
        except Exception, err:
            logging.error('%s in %s' % (err, self.file))
            client.broadcast('umode:W', ':%s ERROR %s found %s in %s' % \
                    (SRV_DOMAIN, client.client_ident(), err, self.file))
            client.broadcast(client.nick, ':%s NOTICE %s :%s is temporarily out of order.' % \
                    (SRV_DOMAIN, client.nick, command.upper()))


class Scripts(object):
    def __init__(self):
        self.dir = scripts_dir
        self.server = 0
        self.commands = {}
        self.cmodes = {}
        self.umodes = {}
        self.threads = []
        self.i = {
            'commands': self.commands,
            'cmodes': self.cmodes,
            'umodes': self.umodes
        }

    def load(self, script, client=None):
        """
        Executes a script with init namespace,
        Determines if it's already loaded,
        Places into the correct dictionary.
        """
        try:
            (provides, s) = self.init(script, client, True)
        except:
            return
        err = None
        for item in provides:
            description = 'No description.'
            d = item.split(':')
            if len(d) > 2: description = d[2]
            if d[0] == 'command':
                for i in d[1].split(','):
                    if i in self.commands.keys():
                        err = "%s appears to already be loaded." % i
                    else:
                        self.commands[i] = [s, description]
                    if client:
                        client.broadcast(client.nick, ':%s NOTICE %s :Loaded %s %s (%s)' % \
                        (SRV_DOMAIN, client.nick, d[0], i, description))
                    logging.info('Loaded %s %s (%s)' % (d[0], i, description))
            elif d[0] == 'cmode':
                for i in d[1].split(','):
                    if i in self.cmodes:
                        err = "%s appears to already be loaded." % i
                    else:
                        self.cmodes[i] = [s, description]
                        if self.server:
                            for channel in self.server.channels.values():
                                channel.supported_modes[i] = description
                    if client:
                        client.broadcast(client.nick, ':%s NOTICE %s :Loaded %s %s (%s)' % \
                        (SRV_DOMAIN, client.nick, d[0], i, description))
                    logging.info('Loaded %s %s (%s)' % (d[0], i, description))
            elif d[0] == 'umode':
                for i in d[1].split(','):
                    if i in self.umodes:
                        err = "%s appears to already be loaded." % i
                    else:
                        self.umodes[i] = [s, description]
                        if self.server:
                            for user in self.server.clients.values():
                                user.supported_modes[i] = description
                    if client:
                        client.broadcast(client.nick, ':%s NOTICE %s :Loaded %s %s (%s)' % \
                        (SRV_DOMAIN, client.nick, d[0], i, description))
                    logging.info('Loaded %s %s (%s)' % (d[0], i, description))
            else:
                err = "%s doesn't provide anything I can recognize." % (
                    self.dir + script)
                if client:
                    client.broadcast(client.nick, ":%s NOTICE %s :%s" %
                                     (SRV_DOMAIN, client.nick, err))
                logging.error(err)

    def unload(self, script, client=None):
        try:
            provides = self.init(script, client, loading=False)
        except:
            return
        err = ''
        if not provides: return
        for item in provides:
            description = 'No description.'
            d = item.split(':')
            if len(d) > 2: description = d[2]
            if d[0] == 'command':
                for i in d[1].split(','):
                    if i in self.commands:
                        del self.commands[i]
                        err = "Unloaded %s %s (%s)" % (d[0], i, description)
                        if client:
                            client.broadcast(client.nick, ":%s NOTICE %s :%s" %
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
                                    del channel.modes[script]
                                    if client:
                                        client.broadcast(
                                            'cmode:' + d[1], ':%s MODE %s -%s' %
                                            (SRV_DOMAIN, channel.name, i))
                        del self.cmodes[i]
                        err = "Unloaded %s %s (%s)" % (d[0], i, description)
                        if client:
                            client.broadcast(client.nick, ":%s NOTICE %s :%s" %
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
                                    del user.modes[i]
                                    if client:
                                        client.broadcast(
                                            'umode:' + i, ':%s MODE %s -%s' %
                                            (SRV_DOMAIN, user.nick, i))
                    del self.umodes[i]
                    err = "Unloaded %s %s (%s)" % (d[0], i, description)
                    if client:
                        client.broadcast(client.nick, ":%s NOTICE %s :%s" %
                                         (SRV_DOMAIN, client.nick, err))
                    logging.info(err)
            else:
                err = "%s doesn't provide anything I can recognize." % (
                    self.dir + script)
                if client:
                    client.broadcast(client.nick, ":%s NOTICE %s :%s" %
                                     (SRV_DOMAIN, client.nick, err))
                logging.error(err)

    def init(self, script, client=None, return_script=False, loading=True):
        if self.dir: script = Script(self.dir + script)
        else: raise Exception('self.dir undefined.')
        try:
            script.execute(
                {'init': loading,
                 'client': client,
                 'server': self.server})
        except Exception, err:
            if not client: logging.error('%s in %s' % (err, script.file))
            else:
                client.broadcast(client.nick, ':%s NOTICE %s :%s in %s' %
                                 (SRV_DOMAIN, client.nick, err, script.file))
            return ()
        provides = []
        if 'provides' in script.env.keys():
            if type(script['provides']) == str:
                provides.append(script['provides'])
            elif type(script['provides']) == list:
                provides = script['provides']
            else:
                if client:
                    client.broadcast(client.nick, ":%s NOTICE %s :Incorrect type %s used to contain 'provides' in %s" % \
                (SRV_DOMAIN, client.nick, type(script['provides']), script.file))
                else:
                    logging.error(
                        "Incorrect type %s used to contain 'provides' in %s" %
                        (type(s['provides']), script.file))
                return ()
            if return_script:
                return (provides, script)
            return provides


def sha1sum(text):
    return (hashlib.sha1(text).hexdigest())


class tabulate(object):
    "Print a list of dictionaries as a table"

    def __init__(self, fmt, sep=' ', ul=None):
        super(tabulate, self).__init__()
        self.fmt = str(sep).join('{lb}{0}:{1}{rb}'.format(key, width,
                                                          lb='{',
                                                          rb='}')
                                 for heading, key, width in fmt)
        self.head = {key: heading for heading, key, width in fmt}
        self.ul = {
            key: str(ul) * width
            for heading, key, width in fmt
        } if ul else None
        self.width = {key: width for heading, key, width in fmt}

    def row(self, data):
        return (self.fmt.format(
            **
            {k: str(data.get(k, ''))[:w]
             for k, w in self.width.iteritems()}))

    def __call__(self, dataList):
        _r = self.row
        res = [_r(data) for data in dataList]
        res.insert(0, _r(self.head))
        if self.ul:
            res.insert(1, _r(self.ul))
        return ('\n'.join(res))


def format(data):
    fmt = []
    tmp = {}
    r_append = 0
    for item in data:
        for key, value in item.items():
            if not key in tmp.keys():
                if value: tmp[key] = len(str(value))
            elif len(str(value)) > tmp[key]:
                if value: tmp[key] = len(str(value))
    for key, value in tmp.items():
        if (key == 'Hash') or (key == 'State'): r_append = (key, key, value)
        else: fmt.append((key, key, value))
    if r_append: fmt.append(r_append)
    return (fmt)


def tconv(seconds):
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    weeks, days = divmod(days, 7)
    months, weeks = divmod(weeks, 4)
    years, months = divmod(months, 12)
    s = ""
    if years:
        if years == 1: s += "%i year, " % (years)
        else: s += "%i years, " % (years)
    if months:
        if months == 1: s += "%i month, " % (months)
        else: s += "%i months, " % (months)
    if weeks:
        if weeks == 1: s += "%i week, " % (weeks)
        else: s += "%i weeks, " % (weeks)
    if days:
        if days == 1: s += "%i day, " % (days)
        else: s += "%i days, " % (days)
    if hours:
        if hours == 1: s += "%i hour " % (hours)
        else: s += "%i hours " % (hours)
    if minutes:
        if len(s) > 0:
            if minutes == 1: s += "and %i minute" % (minutes)
            else: s += "and %i minutes" % (minutes)
        else:
            if minutes == 1: s += "%i minute" % (minutes)
            else: s += "%i minutes" % (minutes)
    if s == '': s = 'a few seconds'
    return s


# Fork a child and end the parent (detach from parent)
# Change some defaults so the daemon doesn't tie up dirs, etc.
class Daemon:
    def __init__(self, pidfile):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)  # End parent
        except OSError, e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" %
                             (e.errno, e.strerror))
            sys.exit(-2)
        os.setsid()
        os.umask(0)
        try:
            pid = os.fork()
            if pid > 0:
                try:
                    # TODO: Read the file first and determine if already running.
                    f = file(pidfile, 'w')
                    f.write(str(pid))
                    f.close()
                except IOError, e:
                    logging.error(e)
                    sys.stderr.write(repr(e))
                sys.exit(0)  # End parent
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" %
                             (e.errno, e.strerror))
            sys.exit(-2)
        for fd in (0, 1, 2):
            try:
                os.close(fd)
            except OSError:
                pass


def re_to_irc(r, displaying=True):
    if displaying:
        r = re.sub('\\\.', '.', r)
        r = re.sub('\.\*', '*', r)
    else:
        r = re.sub('\.', '\\\.', r)
        r = re.sub('\*', '.*', r)
    return (r)


# TODO: memoize
def lookup(addr):
    try:
        return (socket.gethostbyaddr(addr)[0])
    except:
        return (None)


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
    description = "The %sPsybernetics%s IRC Server." % (color.orange, color.end)
    epilog = "Using the %s-k%s and %s-c%s options together enables SSL and plaintext connections over the same port." % \
        (color.blue, color.end, color.blue, color.end)

    parser = optparse.OptionParser(prog=prog, version=SRV_VERSION, description=description, epilog=epilog)
    parser.set_usage(sys.argv[0] + " -f --preload --debug")

    parser.add_option("--start", dest="start", action="store_true", default=True, help="(default)")
    parser.add_option("--stop", dest="stop", action="store_true", default=False)
    parser.add_option("--restart", dest="restart", action="store_true", default=False)
    parser.add_option("--pidfile", dest="pidfile", action="store", default='psyrcd.pid')
    parser.add_option("--logfile", dest="logfile", action="store", default=None)
    parser.add_option("-a", "--address", dest="listen_address", action="store", default='0.0.0.0')
    parser.add_option("-p", "--port", dest="listen_port", action="store", default='6667')
    parser.add_option("-f", "--foreground", dest="foreground", action="store_true")
    parser.add_option("--run-as", dest="run_as",action="store", default=None, help="(defaults to the invoking user)")
    parser.add_option("--scripts-dir", dest="scripts_dir",action="store", default='scripts', help="(defaults to ./scripts/)")
    parser.add_option("--preload", dest="preload", action="store_true",default=False, help="Preload all available scripts.")
    parser.add_option("--debug", dest="debug", action="store_true",default=False, help="Sets read_on_exec to True for live development.")
    parser.add_option("-k", "--key", dest="ssl_key",action="store", default=None)
    parser.add_option("-c", "--cert", dest="ssl_cert",action="store", default=None)
    parser.add_option("--ssl-help", dest="ssl_help",action="store_true",default=False)
#    parser.add_option("--link-help", dest="link_help",action="store_true",default=False)
    (options, args) = parser.parse_args()

    if options.ssl_help:
        print """Keys and certs can be generated with:
$ %sopenssl%s genrsa 1024 >%s key%s
$ %sopenssl%s req -new -x509 -nodes -sha1 -days 365 -key %skey%s > %scert%s""" % \
(color.blue, color.end, color.orange, color.end, color.blue, color.end, color.orange, color.end, color.orange, color.end)
        raise SystemExit

    if (pwd.getpwuid(os.getuid())[2] == 0) and (options.run_as == None):
        logging.info("Running as root is not permitted.")
        logging.info("Please use --run-as")
        raise SystemExit

    if options.run_as:
        if not OPER_USERNAME:
            OPER_USERNAME = options.run_as
        try:
            uid = pwd.getpwnam(options.run_as)[2]
            os.setuid(uid)
            logging.info("Now running as %s." % options.run_as)
        except:
            logging.info("Couldn't switch to user %s" % options.run_as)
            raise SystemExit

    if options.logfile:
        logfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),
                               options.logfile)
        log = logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s [%(levelname)s] %(message)s',
            filename=logfile,
            filemode='a')
    else:
        log = logging.basicConfig(level=logging.DEBUG,
                                  format='[%(levelname)s] %(message)s')

    # Handle start/stop/restart commands.
    if options.stop or options.restart:
        pid = None
        try:
            f = file('psyrcd.pid', 'r')
            pid = int(f.readline())
            f.close()
            os.unlink('psyrcd.pid')
        except ValueError, e:
            sys.stderr.write('Error in pid file `psyrcd.pid`. Aborting\n')
            sys.exit(-1)
        except IOError, e:
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

    if OPER_PASSWORD == True:
        OPER_PASSWORD = hashlib.new('sha512',str(os.urandom(20))).hexdigest()[:20]

    if not sys.stdin.isatty():
        OPER_PASSWORD = sys.stdin.read().strip('\n').split(' ', 1)[0]

    # Detach from console, reparent to init
    if not options.foreground:
        print "Netadmin login: %s/oper %s %s%s" % \
            (color.green, OPER_USERNAME, OPER_PASSWORD, color.end)
        Daemon(options.pidfile)
    else:
        logging.debug("Netadmin login: %s/oper %s %s%s" % \
            (color.green, OPER_USERNAME, OPER_PASSWORD, color.end))

    # Hash the password in memory.
    OPER_PASSWORD = hashlib.sha512(OPER_PASSWORD).hexdigest()

    if options.ssl_cert and options.ssl_key:
        logging.info("SSL Enabled.")

    if options.logfile:
        logging.info("Logging to %s" % (logfile))

    # Set variables for processing script files:
    this_dir = os.path.abspath(os.path.curdir) + os.path.sep
    scripts_dir = this_dir + options.scripts_dir + os.path.sep
    if os.path.isdir(scripts_dir):
        logging.info("Scripts directory: %s" % scripts_dir)
    else:
        scripts_dir = False

    # Start
    ircserver = IRCServer((options.listen_address, int(options.listen_port)), IRCClient)
    try:
        logging.info('Starting psyrcd on %s:%s' %
                     (options.listen_address, options.listen_port))
        if options.preload and scripts_dir:
            for filename in os.listdir(scripts_dir):
                if os.path.isfile(scripts_dir + filename):
                    ircserver.scripts.load(filename)
        ircserver.serve_forever()
    except socket.error, e:
        logging.error(repr(e))
        sys.exit(-2)
    except KeyboardInterrupt:
        ircserver.shutdown()
        if options.preload and scripts_dir:
            scripts = []
            for x in ircserver.scripts.i.values():
                for script in x.values():
                    scripts.append(script[0].file)
            scripts = set(scripts)
            for script in scripts:
                ircserver.scripts.unload(script[script.rfind(os.sep) + 1:])
        logging.info('Bye.')
        raise SystemExit
