# replace.py for Psyrcd.
# Implements channel mode +replace
#
# This channel mode replaces phrases in privmsg lines.
# Usage: /quote mode #channel +replace:from_phrase,to_phrase,...
#        /quote mode #channel -replace:phrase1,...
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
MODE_NAME  = "replace"
SRV_DOMAIN = cache['config']['SRV_DOMAIN']

if 'init' in dir():
    provides = "cmode:%s:Replaces unwanted phrases." % MODE_NAME

if 'display' in dir():
    output = str(channel.modes[MODE_NAME])

if 'set' in dir():
    if set:
        if not MODE_NAME in channel.modes or \
            not isinstance(channel.modes[MODE_NAME], list):
            channel.modes[MODE_NAME] = []
        
        # Ensure only tuple pairs are in the structure for this mode
        f = lambda x: isinstance(x, tuple)
        channel.modes[MODE_NAME] = filter(f, channel.modes[MODE_NAME])
        
        # Check args are an even number
        if not len(args) % 2:
            
            # Turn into tuples
            def chunks(l, n):
                for i in xrange(0, len(l), n):
                    yield l[i:i+n]
            
            args = [tuple(x) for x in chunks(args, 2)]

            new_phrases     = []
            current_phrases = [x[0] for x in channel.modes[MODE_NAME]]

            for new_phrase_pair in args:
                if new_phrase_pair[0] in current_phrases:
                    continue
                new_phrases.append(new_phrase_pair)

            channel.modes[MODE_NAME].extend(new_phrases)

        cancel = ""
        response = ":%s MODE %s +%s:%s" % \
            (client.client_ident(True), channel.name, MODE_NAME, str(new_phrases))
        client.broadcast(channel.name, response)

    else: # Handle removing individual phrases
        from copy import deepcopy
        removed_phrases = []
        current_pairs   = deepcopy(channel.modes[MODE_NAME])
        for phrase in args:
            for i, pair in enumerate(current_pairs):
                if phrase.lower() == pair[0].lower():
                    del channel.modes[MODE_NAME][i]
                    removed_phrases.append(phrase.lower())
        cancel = ""
        response = ":%s MODE %s -%s:%s" % \
            (client.client_ident(True), channel.name, MODE_NAME, str(removed_phrases))
        client.broadcast(channel.name, response)

# Replace phrases when encountered
if 'func' in dir() and func.func_name == "handle_privmsg":
    params = params.split(":",1)
    line = params[1].split()
    for arg in channel.modes[MODE_NAME]:
        if isinstance(arg, tuple):
            for i, phrase in enumerate(line):
                if phrase.lower() == arg[0].lower():
                    line[i] = arg[1]
    params[1] = ' '.join(line)
    params = ':'.join(params)


