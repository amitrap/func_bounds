import idautils
import idaapi
import idc

def get_text_segment():
	for seg in idautils.Segments():
		if idc.SegName(seg).startswith(".text"):
			return seg
	raise LookupError
def get_funcs_bounds():
	seg = get_text_segment()
	return [{func: list(idautils.Chunks(func)) for func in idautils.Functions(idc.SegStart(seg), idc.SegEnd(seg))}, dict(idautils.Names())]
			
def main():
	file(GetInputFile() + ".bounds.auto.py", "wb").write("%r" % (get_funcs_bounds()))
	print "get_funcs_bounds() SUCCESS"
if __name__ == "__main__":
	main()