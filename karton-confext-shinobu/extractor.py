#!/usr/bin/env python3
from pythonnet import load
load("coreclr")

import clr
clr.AddReference("dnlib")

import dnlib
from dnlib.DotNet import *

import sys, json, os

def extract(file: str) -> dict:
	mod = dnlib.DotNet.ModuleDefMD.Load(file)
	config = {}

	# v------------ extraction logic goes here ------------v

	insts = list(mod.Types[6].Methods[0].Body.Instructions)

	for val, name in zip(insts[::2], insts[1::2]):
		try:
			config[name.Operand.name.ToString()] = val.Operand
		except:
			pass

	# ^------------ extraction logic goes here ------------^

	return config

if __name__ == '__main__':

	files = sys.argv[1:]
	if not sys.stdin.isatty():
		files += [f.strip() for f in sys.stdin]

	if not files:
		print('Usage:\n	Files : ARGV + STDIN\n	Config: STDOUT')
		exit(1)

	for file in files:
		file = os.path.abspath(os.path.expanduser(os.path.expandvars(file)))
		try:
			print('Processing,', file, file=sys.stderr)
			print(json.dumps(extract(file)))
		except Exception as e:
			print('Failed to extract from', file, 'because', e, file=sys.stderr)