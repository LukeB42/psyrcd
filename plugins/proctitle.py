__package__ = [{"name": "spt", "type": "command",
                "description": "Sets process title."}]

def spt(ctx):
    pass

def __init__(ctx):
    __package__[0]["callable"] = spt
    try:
        import setproctitle
        setproctitle.setproctitle('psyrcd')
    except Exception:
        pass

def __del__(ctx):
    pass
