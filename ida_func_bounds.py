# This script is using idapython in order to enumerate all function, collecting their chunks bounds and names
# It generates a "*.bounds.auto.py" output file for "*" holding results in the following format: 
# [{func_addr: [(chunk_start_addr, chunk_end_addr), ...], ...}, {func_addr: "func_name", ...}]
import idautils
import idaapi
import idc

# If you want this script to generate functions only from .text section, set this global to True
TEXT_SECTION_ONLY = False

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
	seg_start, seg_end = None, None
	if TEXT_SECTION_ONLY:
		seg = get_text_segment()
		seg_start = idc.SegStart(seg)
		seg_end = idc.SegEnd(seg)
	return [{func: list(idautils.Chunks(func)) for func in idautils.Functions(seg_start, seg_end)}, dict(idautils.Names())]
			
def main():
	"""
	Main logics, generates result file for function bounds
	"""
	func_bounds_list = get_funcs_bounds()
	file(GetInputFile() + ".bounds.auto.py", "wb").write("%r" % (func_bounds_list))
	print "get_funcs_bounds() SUCCESS! Funcs Count = %d" %(len(func_bounds_list[0]))
	
if __name__ == "__main__":
	idaapi.autoWait()
	main()