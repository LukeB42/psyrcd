if 'init' in dir():
  provides="command:spt:Sets process title."
  try:
    import sys, setproctitle
    setproctitle.setproctitle('psyrcd')
  except: pass
