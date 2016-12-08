import os
import re
import angr

# Adjust IDA PATH according to configuration on your machine
BINARIES_NAME_PATTERN = "^.*"

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
ARCH_DIR = os.path.join(BASE_DIR, r"bin_repo/amd64") # Change this to another arch (e.g. amd64)
UNSTRIPPED_BINARIES_PATH = os.path.join(ARCH_DIR, "unstripped")
STRIPPED_BINARIES_PATH = os.path.join(ARCH_DIR, "stripped")

def gen_blocks_addr_set(elf_path):
	proj = angr.Project(elf_path, load_options={'auto_load_libs': False})
	cfg = proj.analyses.CFG()
	funcs_basic_blocks_dict = {func:proj.kb.functions[func].block_addrs for func in proj.kb.functions.keys()}
	return frozenset({k:frozenset(funcs_basic_blocks_dict[k]) for k in funcs_basic_blocks_dict.keys()}.items())

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
		i = i + 1
		unstripped_file_path = os.path.join(unstripped_dir_path, name)
		stripped_file_path = os.path.join(stripped_dir_path, name)
			
		print "(%d/%d) Parsing bounds for unstripped=%s stripped=%s" %(i, len(binaries_list), unstripped_file_path, stripped_file_path)
	
		stripped_set = gen_blocks_addr_set(stripped_file_path)
		unstripped_set = gen_blocks_addr_set(unstripped_file_path)
		undiscovered_func_bounds = frozenset(unstripped_set) - frozenset(stripped_set)
		
		unstripped_count += len(unstripped_set)
		undiscovered_count += len(undiscovered_func_bounds)
		print 'current: undiscovered funcs count = %d, total funcs count = %d' %(undiscovered_count, unstripped_count)
	print 'Results for files with pattern "%s" is: (undiscovered count/func count) (%d/%d), %f%%' %(BINARIES_NAME_PATTERN, undiscovered_count, unstripped_count, (float(undiscovered_count) / unstripped_count) * 100.0)
	
def main():
	compare_all_bounds(UNSTRIPPED_BINARIES_PATH, STRIPPED_BINARIES_PATH)
	
if __name__ == "__main__":
	main()