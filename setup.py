#!/usr/bin/env python2
# _*_ coding: utf-8 _*_
import os
import sys
import shutil
from setuptools import setup, find_packages

banner = """
██████╗ ███████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗███████╗████████╗██╗ ██████╗███████╗   
██╔══██╗██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝╚══██╔══╝██║██╔════╝██╔════╝   
██████╔╝███████╗ ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗     ██║   ██║██║     ███████╗   
██╔═══╝ ╚════██║  ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝     ██║   ██║██║     ╚════██║   
██║     ███████║   ██║   ██████╔╝███████╗██║  ██║██║ ╚████║███████╗   ██║   ██║╚██████╗███████║██╗
╚═╝     ╚══════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝╚══════╝╚═╝
"""

def main():
	if len(sys.argv) < 2:
		print "Accepted arguments are: install, uninstall"
		raise SystemExit

	if sys.argv[1].lower() == "install":
		install()

	if sys.argv[1].lower() == "uninstall":
		uninstall()

def install():
	print banner
	# install deps and module
	data_files = ()
	setup(name='psyrcd',
		version="0.16",
		description='A pure-python IRCD',
		author='Luke Brooks',
		author_email='luke@psybernetics.org',
		url='http://src.psybernetics.org',
		download_url = 'https://github.com/LukeB42/psyrcd/tarball/0.0.1',
		data_files = data_files,
		packages=[],
		include_package_data=True,
		install_requires=[
		],
		keywords=["irc", "ircd"]
	)

	if os.path.exists('/etc/systemd/system'):
		print "Installing systemd service definition."
		shutil.copyfile("psyrcd.service","/etc/systemd/system/psyrcd.service")
	else:
		print "Installing init script to /etc/init.d/psyrcd"
		shutil.copyfile("psyrcd","/etc/init.d/psyrcd")

	print "Moving psyrcd.py to /usr/bin/psyrcd"
	shutil.copyfile("./psyrcd.py", "/usr/bin/psyrcd")

	print "Making /usr/bin/psyrcd executable."
	os.chmod("/usr/bin/psyrcd", 0755)
	print 'Check "psyrcd --help" for options.'


def uninstall():

	# remove systemd unit/init script
	if os.path.exists("/etc/systemd/system/psyrcd.service"):
		print "Removing /etc/systemd/system/psyrcd.service"
		os.remove("/etc/systemd/system/psyrcd.service")

	if os.path.exists("/etc/init.d/psyrcd"):
		print "Removing /etc/init.d/psyrcd"
		os.remove("/etc/init.d/psyrcd")

	if os.path.exists("/usr/bin/psyrcd"):
		print "Removing /usr/bin/psyrcd"
		os.remove("/usr/bin/psyrcd")

if __name__ == "__main__":
	if sys.version_info[0] != 2:
		print("Python 3.x isn't supported by Psyrcd yet.")
		sys.exit(0)
	main()
