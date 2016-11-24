import sys

def main(unstripped_func_bounds_file_path, stripped_func_bounds_file_path):
	
	unstripped_bounds_dict, unstripped_names_dict = tuple(eval(file(unstripped_func_bounds_file_path, "rb").read()))
	stripped_bounds_dict, stripped_names_dict = tuple(eval(file(stripped_func_bounds_file_path, "rb").read()))
	
	unstripped_bounds_dict = {k:frozenset(unstripped_bounds_dict[k]) for k in unstripped_bounds_dict.keys()}
	stripped_bounds_dict = {k:frozenset(stripped_bounds_dict[k]) for k in stripped_bounds_dict.keys()}
	
	undiscovered_func_bounds = frozenset(unstripped_bounds_dict.items()) - frozenset(stripped_bounds_dict.items())
	
	print "IDA undiscovered %f%% procedures from stripped-binary-params: %s" %((float(len(undiscovered_func_bounds)) / len(unstripped_bounds_dict)) * 100.0, stripped_func_bounds_file_path)
	if len(undiscovered_func_bounds) > 0:
		print "List of %d functions which were undiscovered successfully after stripping:" %(len(undiscovered_func_bounds))
		for func in undiscovered_func_bounds:
			print unstripped_names_dict[func[0]]
	
if __name__ == "__main__":
	if len(sys.argv) != 3:
		print "USAGE: %s <unstripped func bounds py file path> <stripped func bounds py file path>"
	else:
		main(sys.argv[1], sys.argv[2])