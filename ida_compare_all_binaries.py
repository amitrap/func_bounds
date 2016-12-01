import os
import subprocess
import time
import re

# Adjust IDA PATH according to configuration on your machine
IDA_PATH = r'C:\Program Files (x86)\IDA 6.4\idaq.exe'
BINARIES_NAME_PATTERN = "gcc_[a-zA-Z]+_32_O0_[a-zA-Z]+"
BOUNDS_NAME_PATTERN = BINARIES_NAME_PATTERN + r"\.bounds\.auto\.py"

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
UNSTRIPPED_BINARIES_PATH = os.path.join(BASE_DIR, "binary")
STRIPPED_BINARIES_PATH = os.path.join(BASE_DIR, "binary_strip")
IDA_FUNC_BOUNDS_PATH = os.path.join(BASE_DIR, "ida_func_bounds.py")
IDA_COMMANDLINE = IDA_PATH + r' -B -S"' + IDA_FUNC_BOUNDS_PATH + '" %s'

def run_command_async(cmdline):
	"""
	Runs given commandline and return (out, err) results
	"""
	print "Executing %s" % cmdline
	p = subprocess.Popen(cmdline.split())
	return p

def generate_all_bounds(binpath):
	p_list = []
	dirpath, dirnames, filenames = os.walk(binpath).next()
	for name in filenames:
		if not re.match(BINARIES_NAME_PATTERN, name):
			continue
		p_list.append(run_command_async(IDA_COMMANDLINE % os.path.join(dirpath, name)))
	raw_input("IDA Finished parsing ALL?")
	for p in p_list:
		try:
			p.terminate()	
		except:
			pass
			
def delete_all_temps(binpath, ext_list):
	dirpath, dirnames, filenames = os.walk(binpath).next()
	for name in filenames:
		for ext in ext_list:
			if name.endswith(ext):
				os.unlink(os.path.join(dirpath, name))
def regenerate_all_bounds(binpath):
	temp_exts = [".id0", ".id1", ".til", ".nam"]
	delete_all_temps(binpath, temp_exts)
	generate_all_bounds(binpath)
	time.sleep(5)
	delete_all_temps(binpath, temp_exts)
	
def compare_all_bounds(unstripped_path, stripped_path):
	undiscovered_count = 0
	unstripped_count = 0
	
	dirpath, dirnames, filenames = os.walk(unstripped_path).next()
	for name in filenames:
		if not re.match(BOUNDS_NAME_PATTERN, name):
			continue
		try:		
			unstripped_func_bounds_file_path = os.path.join(unstripped_path, name)
			stripped_func_bounds_file_path = os.path.join(stripped_path, name)
			
			print "Parsing bounds for unstripped=%s stripped=%s" %(unstripped_func_bounds_file_path, stripped_func_bounds_file_path)
			
			unstripped_bounds_dict, unstripped_names_dict = tuple(eval(file(unstripped_func_bounds_file_path, "rb").read()))
			stripped_bounds_dict, stripped_names_dict = tuple(eval(file(stripped_func_bounds_file_path, "rb").read()))
		
			unstripped_bounds_dict = {k:frozenset(unstripped_bounds_dict[k]) for k in unstripped_bounds_dict.keys()}
			stripped_bounds_dict = {k:frozenset(stripped_bounds_dict[k]) for k in stripped_bounds_dict.keys()}
		
			undiscovered_func_bounds = frozenset(unstripped_bounds_dict.items()) - frozenset(stripped_bounds_dict.items())
			
			unstripped_count += len(unstripped_bounds_dict)
			undiscovered_count += len(undiscovered_func_bounds)
		except IOError:
			pass
			
	print 'Results for files with pattern "%s" is: (undiscovered count/func count) (%d/%d), %f%%' %(BINARIES_NAME_PATTERN, undiscovered_count, unstripped_count, (float(undiscovered_count) / unstripped_count) * 100.0)
		
def main():
	regenerate_all_bounds(STRIPPED_BINARIES_PATH)
	regenerate_all_bounds(UNSTRIPPED_BINARIES_PATH)
	compare_all_bounds(UNSTRIPPED_BINARIES_PATH, STRIPPED_BINARIES_PATH)
	
if __name__ == "__main__":
	main()