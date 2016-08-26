# replace.py for Psyrcd.
# Implements channel mode +G.
#
# This channel mode replaces phrases in privmsg lines.
# Usage: /quote mode #channel +G:from_phrase,to_phrase,...
#        /quote mode #channel -G:phrase1,...
#
# Luke Brooks, 2015
# MIT License
#

if 'init' in dir():
    provides = "cmode:G:Substitutes phrases."

if 'display' in dir():
    if client.oper:
        phrases = str(channel.modes["G"])
        output  = "phrase%s: %s" % ('s' if len(phrases) > 1 else '', phrases)

if 'setting_mode' in dir():
    if set:
        if not "G" in channel.modes or \
            not isinstance(channel.modes["G"], list):
            channel.modes["G"] = []
        
        # Ensure only tuple pairs are in the structure for this mode
        f = lambda x: isinstance(x, tuple)
        channel.modes["G"] = list(filter(f, channel.modes["G"]))
        
        # Check args are an even number
        if not len(args) % 2:
            
            # Turn into tuples
            def chunks(l, n):
                for i in range(0, len(l), n):
                    yield l[i:i+n]
            
            args = [tuple(x) for x in chunks(args, 2)]

            new_phrases     = []
            current_phrases = [x[0] for x in channel.modes["G"]]

            for new_phrase_pair in args:
                if new_phrase_pair[0] in current_phrases:
                    continue
                new_phrases.append(new_phrase_pair)

            channel.modes["G"].extend(new_phrases)

        cancel = ""
        response = ":%s MODE %s +G: %s" % \
            (client.client_ident(True), channel.name, str(new_phrases))
        client.broadcast(channel.name, response)

    else: # Handle removing individual phrases
        from copy import deepcopy
        removed_phrases = []
        current_pairs   = deepcopy(channel.modes["G"])
        for phrase in args:
            for i, pair in enumerate(current_pairs):
                if phrase.lower() == pair[0].lower():
                    del channel.modes["G"][i]
                    removed_phrases.append(phrase.lower())
        if args:
            cancel = ""
            response = ":%s MODE %s -G: %s" % \
                (client.client_ident(True), channel.name, str(removed_phrases))
            client.broadcast(channel.name, response)

# Replace phrases when encountered
if 'func' in dir() and func.__name__ == "handle_privmsg":
    params = params.split(":",1)
    line = params[1].split()
    for arg in channel.modes["G"]:
        if isinstance(arg, tuple):
            for i, phrase in enumerate(line):
                if phrase.lower() == arg[0].lower():
                    line[i] = arg[1]
    params[1] = ' '.join(line)
    params = ':'.join(params)


