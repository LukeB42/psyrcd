import logging
import datetime as dt

__package__ = [{"name": "news", "type": "command",
                "description": "Provides a command interface to Emissary."}]

API_KEY       = ""
EMISSARY_HOST = "localhost:6362"

_emissary_client = None


def _emident(ctx):
    return "Emissary!services@" + ctx.client.server.config.server.domain


def emsg(ctx, msg, indent=0):
    client = ctx.client
    ident = _emident(ctx)
    if indent:
        client.broadcast(client.nick, ":%s NOTICE * :%s%s" % (ident, " " * indent, msg))
    else:
        client.broadcast(client.nick, ":%s NOTICE * :%s" % (ident, msg))


def transmit_article_titles(ctx, res):
    if 'message' in res[0]:
        emsg(ctx, res[0]['message'])
    elif res[1] == 200:
        for d in res[0]['data']:
            if 'feed' not in d:
                d['feed'] = ''
            if '://' not in d['url']:
                d['url'] = "http://" + d['url']
            if d['content_available']:
                emsg(ctx, "%s: \x037%s\x0F" % (d['feed'], d['title']))
            else:
                emsg(ctx, "%s: %s" % (d['feed'], d['title']))
            if 'created' in d:
                emsg(ctx, "%s %s \x0314%s\x0F" % (
                    str(dt.datetime.fromtimestamp(int(d['created'])).strftime('%H:%M:%S %d/%m/%Y')),
                    d['uid'], d['url']))
    else:
        emsg(ctx, "Error.")


def transmit_feed_objects(ctx, res):
    (resp, status) = res
    if 'data' in resp.keys():
        resp = resp['data']
    if type(resp) == list:
        for fg in resp:
            transmit_feed_group(ctx, fg)
    else:
        transmit_feed_group(ctx, resp)


def transmit_feed_group(ctx, resp):
    if 'message' in resp:
        emsg(ctx, resp['message'])
    elif 'feeds' in resp and 'created' in resp:
        created = dt.datetime.fromtimestamp(int(resp['created'])).strftime('%H:%M:%S %d/%m/%Y')
        if 'active' in resp and resp['active'] == True:
            emsg(ctx, "\x033%s\x0F (created %s)" % (resp['name'], created))
        else:
            emsg(ctx, "%s (created %s)" % (resp['name'], created))
        for feed in resp['feeds']:
            transmit_feed(ctx, feed)
    else:
        transmit_feed(ctx, resp)


def transmit_feed(ctx, feed):
    if 'created' in feed:
        created = dt.datetime.fromtimestamp(int(feed['created'])).strftime('%H:%M:%S %d/%m/%Y')
    if 'active' in feed and feed['active'] == True:
        emsg(ctx, "\x033%s\x0F" % feed['name'], 2)
    else:
        emsg(ctx, "%s" % feed['name'], 2)
    emsg(ctx, "          URL: %s" % feed['url'], 2)
    if feed['running'] == True:
        emsg(ctx, "      Running: \x033%s\x0F" % (feed['running']), 2)
    elif feed['running'] == False:
        emsg(ctx, "      Running: \x031%s\x0F" % (feed['running']), 2)
    else:
        emsg(ctx, "      Running: \x0314Unknown\x0F", 2)
    emsg(ctx, "      Created: %s" % created, 2)
    emsg(ctx, "     Schedule: %s" % feed['schedule'], 2)
    emsg(ctx, "Article count: %s" % "{:,}".format(feed['article_count']), 2)


def news(ctx):
    line_body = ctx.line.body
    raw_params = line_body.split(' ', 1)[1].strip() if ' ' in line_body else ''
    params = raw_params.split()
    c = _emissary_client
    if not c or not params:
        return

    if params[0].startswith('articles'):
        res = c.get(params[0])
        if res:
            transmit_article_titles(ctx, res)

    elif params[0].startswith('feeds'):
        params_str = ' '.join(params)
        res = c.get(params_str)
        if res[1] != 200:
            emsg(ctx, "Error.")
        if '/search/' in params_str or '/articles' in params_str:
            transmit_article_titles(ctx, res)
        else:
            transmit_feed_objects(ctx, res)

    elif params[0] == 'read':
        (resp, status) = c.get('articles/' + params[1])
        if status != 200:
            emsg(ctx, "Error status %i" % status)
        else:
            if not resp['content']:
                emsg(ctx, "No content for %s" % resp['url'])
            else:
                emsg(ctx, resp['title'])
                emsg(ctx, resp['url'])
                emsg(ctx, "")
                for line in resp['content'].split('\n'):
                    emsg(ctx, line)


def __init__(ctx):
    global _emissary_client
    __package__[0]["callable"] = news
    if not API_KEY:
        logging.error("API key undefined in news.py.")
        return
    if _emissary_client is None:
        from emissary.client import Client
        _emissary_client = Client(API_KEY, 'https://%s/v1/' % EMISSARY_HOST,
                                  verify=False, timeout=5.5)


def __del__(ctx):
    global _emissary_client
    _emissary_client = None
