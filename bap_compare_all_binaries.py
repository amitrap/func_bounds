import os
import re
import subprocess
import sys
import time

BINARIES_NAME_PATTERN = "^.*"


def gen_blocks_addr_set(elf_path):
	funcs_dict = {}
	cmdline = "bap %s --dump-symbols" % (elf_path)
	bap_output = subprocess.check_output(cmdline.split(),stderr=subprocess.PIPE)
	time.sleep(0.2)
	for t in bap_output.split("\n"):
		if len(t) == 0 or t[0] != "(" or t[-1] != ")":
			continue
		func_name, chunk_start, chunk_end = t[1:-1].split(" ")
		if func_name not in funcs_dict.keys():
			funcs_dict[func_name] = [(chunk_start, chunk_end)]
		else:
			funcs_dict[func_name] += [(chunk_start, chunk_end)]
	
	funcs_dict = {k:frozenset(funcs_dict[k]) for k in funcs_dict.keys()}
	return frozenset(funcs_dict.values())

def compare_all_bounds(unstripped_dir_path, stripped_dir_path):
	undiscovered_count = 0
	unstripped_count = 0
	
	# Construct a binaries list containing only desired names
	binaries_list = []
	dirpath, dirnames, filenames = os.walk(unstripped_dir_path).next()
	for name in filenames:
		if name.endswith(r".bounds.auto.py") or not re.match(BINARIES_NAME_PATTERN, name):
				continue
		binaries_list.append(name)
	
	# Iterate all binaries, generate sets of basic blocks and compares between stripped+unstripped versions
	i = 0
	for name in binaries_list:
		try:
			i = i + 1
			unstripped_file_path = os.path.join(unstripped_dir_path, name)
			stripped_file_path = os.path.join(stripped_dir_path, name)
				
			print "(%d/%d) Parsing bounds for unstripped=%s stripped=%s" %(i, len(binaries_list), unstripped_file_path, stripped_file_path)
		
			stripped_set = gen_blocks_addr_set(stripped_file_path)
			unstripped_set = gen_blocks_addr_set(unstripped_file_path)
			undiscovered_func_bounds = unstripped_set - stripped_set
			
			unstripped_count += len(unstripped_set)
			undiscovered_count += len(undiscovered_func_bounds)
			print 'current: undiscovered funcs count = %d, total funcs count = %d' %(undiscovered_count, unstripped_count)
		except subprocess.CalledProcessError:
			pass
	print 'Results for files with pattern "%s" is: (undiscovered count/func count) (%d/%d), %f%%' %(BINARIES_NAME_PATTERN, undiscovered_count, unstripped_count, (float(undiscovered_count) / unstripped_count) * 100.0)
	
def main(arch):
	BASE_DIR = os.path.dirname(os.path.realpath(__file__))
	ARCH_DIR = os.path.join(os.path.join(BASE_DIR, r"bin_repo"), arch)
	UNSTRIPPED_BINARIES_PATH = os.path.join(ARCH_DIR, "unstripped")
	STRIPPED_BINARIES_PATH = os.path.join(ARCH_DIR, "stripped")

	compare_all_bounds(UNSTRIPPED_BINARIES_PATH, STRIPPED_BINARIES_PATH)
	
if __name__ == "__main__":
	if len(sys.argv) != 2 or sys.argv[1] not in ("i386", "amd64", "aarch64"):
		print "%s <i386/amd64/aarch64>" %(sys.argv[0])
	else:
		main(sys.argv[1])