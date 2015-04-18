#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
	name='psyrcd',
	version='0.14',
	url='https://github.com/LukeB42/psyrcd',
	download_url='https://github.com/LukeB42/psyrcd/archive/master.zip',
	author='Luke Brooks',
	license='MIT License',
	py_modules=["psyrcd"],
	entry_points={
		'console_scripts': [
			"psyrcd = psyrcd:main"
		]
	},
	description='The Psybernetics IRC server',
	long_description=file('README.md','r').read(),
	keywords=['IRC', 'IRCd'],
)
