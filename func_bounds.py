#!/usr/bin/python
# Used mainly to generate reliable information of function boundaries of an unstripped binary (ELF)
# using DWARF information stored in its .debug section
import subprocess
import sys
import re

def run_command(cmdline):
	"""
	Runs given commandline and return (out, err) results
	"""
	p = subprocess.Popen(cmdline.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	return p.communicate()

def pretty_print_dict(funcs_dict):
	print "FUNCTIONS BOUNDS - "
	for k in funcs_dict:
		print "Func Name: %r" % (k,)
		print "Func bounds (low_pc, high_pc/len) (%d chunks): %r" % (len(funcs_dict[k]), funcs_dict[k])
		print "-------------------"

def main(exe_path):
	"""
	Given an executable path, this function runs objdump to get its parsed DWARF information stored in .debug section
	Then it finds all DIE referencing procedures, extracting their names and chunks boundaries
	"""
	out, err = run_command('objdump --dwarf=info %s' % (exe_path,)) 
	subprog_matches = re.findall(
	r'\(DW_TAG_subprogram\)(.*?)<[0-9a-fA-F]+><[0-9a-fA-F]+>',  out.replace("\n","").replace(" ",""))
	if len(subprog_matches) == 0:
		print "ERROR: No function info was found in .debug section"
		return

	funcs_dict = {}
	for m in subprog_matches:
		try:
			func_name = re.findall("DW_AT_name:(.*?)<", m)[0]
			bounds = (re.findall("DW_AT_low_pc:(.*?)<", m)[0], re.findall("DW_AT_high_pc:(.*?)<", m)[0])
		except IndexError:
			continue
		
		# Accumulate chunks bounds if multiple were found for same function
		if func_name not in funcs_dict.keys():
			funcs_dict[func_name] = [bounds]
		else:
			funcs_dict[func_name] += [bounds]
	pretty_print_dict(funcs_dict)


if __name__ == "__main__":
	# Validate Arguments
	if len(sys.argv) == 2:
		main(sys.argv[1])
	else:
		print "USAGE: %s <executable_path>" % (sys.argv[0],)
