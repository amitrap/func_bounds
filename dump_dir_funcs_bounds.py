#!/usr/bin/python
import os
import sys
import subprocess

def run_command(cmdline):
	p = subprocess.Popen(cmdline.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	return p.communicate()

dirpath, dirnames, filenames = os.walk(sys.argv[1]).next()
for name in filenames:
	f_path = os.path.join(dirpath,name)
	print "Processing... " + f_path
	out, err = run_command("python ./funcs_bounds.py %s" %(f_path,))
	file(f_path + ".bounds", "wb").write(out)
print "Finished successfully!"



