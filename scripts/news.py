# news.py for Psyrcd.
# Implements channel mode +news
# This permits users to read from a live Emissary instance in-situ, including
# searching through articles, reviewing feed status and reading articles
# over IRC. All of the usual Emissary endpoints are supported.
#
#     /operserv scripts load news.py
#     /news feeds?per_page=5
#     /news articles/search/photosynthesis
#     /news read ad8aaf28-0d1d-48c3-a3b9-85bdcaa9ee5b
#
# Luke Brooks, 2015
# MIT License
#
# Emissary can be found at https://github.com/LukeB42/Emissary
#

# Colour key:
# \x02 bold
# \x03 coloured text
# \x1D italic text
# \x0F colour reset
# \x16 reverse colour
# \x1F underlined text
import datetime as dt
logging       = cache['config']['logging']
API_KEY       = ""
EMISSARY_HOST = "localhost:6362"
EM_IDENT      = "Emissary!services@" + cache['config']['SRV_DOMAIN']

def emsg(msg, indent=0):
    if indent:
        client.broadcast(client.nick, ":%s NOTICE * :%s%s" % \
            (EM_IDENT, " " * indent, msg))
    else:
        client.broadcast(client.nick, ":%s NOTICE * :%s" % \
            (EM_IDENT, msg))

def transmit_article_titles(res):
    if 'message' in res[0]:
        emsg(res[0]['message'])
    elif res[1] == 200:
        for d in res[0]['data']:
            if not 'feed' in d:
                d['feed'] = ''
            if not '://' in d['url']:
                d['url'] = "http://" + d['url']
            if d['content_available']:
                emsg("%s: \x037%s\x0F" % (d['feed'], d['title']))
            else:
                emsg("%s: %s" % (d['feed'], d['title']))
            if 'created' in d:
                emsg("%s %s \x0314%s\x0F" % \
                (str(dt.datetime.fromtimestamp(int(d['created']))\
                    .strftime('%H:%M:%S %d/%m/%Y')),
            d['uid'], d['url']))
    else:
        emsg("Error.")

def transmit_feed_objects(res):
    (resp, status) = res
    if 'data' in resp.keys():
        resp = resp['data']
    if type(resp) == list:
        for fg in resp:
            transmit_feed_group(fg)
    else:
        transmit_feed_group(resp)

def transmit_feed_group(resp):
    if 'message' in resp:
        emsg(resp['message'])
    elif 'feeds' in resp and 'created' in resp:
        created = dt.datetime.fromtimestamp(int(resp['created'])).strftime('%H:%M:%S %d/%m/%Y')
        if 'active' in resp and resp['active'] == True:
            emsg("\x033%s\x0F (created %s)" % (resp['name'], created))
        else:
            emsg("%s (created %s)" % (resp['name'], created))
        for feed in resp['feeds']:
            transmit_feed(feed)
    else:
        transmit_feed(resp)

def transmit_feed(feed):
    if 'created' in feed:
        created = dt.datetime.fromtimestamp(int(feed['created'])).strftime('%H:%M:%S %d/%m/%Y')
    if 'active' in feed and feed['active'] == True:
        emsg("\x033%s\x0F" % feed['name'], 2)
    else:
        emsg("%s" % feed['name'], 2)
    emsg("          URL: %s" % feed['url'], 2)
    if feed['running'] == True:
        emsg("      Running: \x033%s\x0F" % (feed['running']), 2)
    elif feed['running'] == False:
        emsg("      Running: \x031%s\x0F" % (feed['running']), 2)
    else:
        emsg("      Running: \x0314Unknown\x0F", 2)
    emsg("      Created: %s" % created, 2)
    emsg("     Schedule: %s" % feed['schedule'], 2)
    emsg("Article count: %s" % "{:,}".format(feed['article_count']), 2)

if 'init' in dir():
    provides = "command:news:Provides a command interface to Emissary."
    if init:
        if not API_KEY:
            logging.error("API key undefined in news.py.")
#            client.broadcast("umode:W", ": There's no API key defined in news.py.")
        if not 'client' in cache:
            from emissary.client import Client
            client = Client(API_KEY,'https://%s/v1/' % EMISSARY_HOST,
                    verify=False, timeout=5.5)
            cache['client'] = client
    else:
        if 'client' in cache:
            del cache['client']

if 'command' in dir():
    cancel = True
    params = params.split()
    c      = cache['client']

    if params[0].startswith('articles'):
        res = c.get(params[0])
        if res:
            transmit_article_titles(res)

    elif params[0].startswith('feeds'):
        params = ' '.join(params[0:])
        res = c.get(params)
        if res[1] != 200: emsg("Error.")
        if '/search/' in params or '/articles' in params:
            transmit_article_titles(res)
        else:
            transmit_feed_objects(res)

    elif params[0] == 'read':
        (resp, status) = c.get('articles/' + params[1])
        if status != 200:
            emsg("Error status %i" % status)
        else:
            if not resp['content']:
                emsg("No content for %s" % resp['url'])
            else:
                title = resp['title']
                url = resp['url']
                created = resp['created']
                content = resp['content']
                emsg(title)
                emsg(url)
                emsg("")
                for line in content.split('\n'):
                    emsg(line)

if 'c' in dir():
    del c

del API_KEY
