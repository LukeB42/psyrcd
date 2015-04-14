if 'init' in dir():
    provides = "command:spt:Sets process title."
    try:
        import setproctitle
        setproctitle.setproctitle('psyrcd')
    except:
        pass
