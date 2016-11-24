#!/usr/bin/python
# This script dumps all function bounds for each file in the given directory using funcs_bounds.py script
# It is used mainly to generate reliable information of function boundaries of unstripped binaries (ELF)
# using DWARF information stored in their .debug section
import os
import sys
import subprocess

FUNC_BOUNDS_SCRIPT_PATH = "./func_bounds.py"

def run_command(cmdline):
	"""
	Runs given commandline and return (out, err) results
	"""
	p = subprocess.Popen(cmdline.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	return p.communicate()

dirpath, dirnames, filenames = os.walk(sys.argv[1]).next()
for name in filenames:
	f_path = os.path.join(dirpath,name)
	print "Processing... " + f_path
	out, err = run_command('python %s %s' % (FUNC_BOUNDS_SCRIPT_PATH, f_path,))
	file(f_path + ".bounds", "wb").write(out)
print "Finished successfully!"



