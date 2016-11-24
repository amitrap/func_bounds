# This script is using idapython in order to enumerate all function within ".text" section, collecting their chunks bounds and names
# It generates a "*.bounds.auto.py" output file for "*" holding results in the following format: 
# [{func_addr: [(chunk_start_addr, chunk_end_addr), ...], ...}, {func_addr: "func_name", ...}]
import idautils
import idaapi
import idc

def get_text_segment():
	"""
	Returns input file ".text" section address
	"""
	for seg in idautils.Segments():
		if idc.SegName(seg).startswith(".text"):
			return seg
	raise LookupError

def get_funcs_bounds():
	"""
	Returns input file functions and their chunks' bounds
	"""
	seg = get_text_segment()
	return [{func: list(idautils.Chunks(func)) for func in idautils.Functions(idc.SegStart(seg), idc.SegEnd(seg))}, dict(idautils.Names())]
			
def main():
	"""
	Main logics, generates result file for function bounds
	"""
	file(GetInputFile() + ".bounds.auto.py", "wb").write("%r" % (get_funcs_bounds()))
	print "get_funcs_bounds() SUCCESS!"
	
if __name__ == "__main__":
	main()