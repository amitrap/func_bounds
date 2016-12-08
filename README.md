General Findings:
======================

i386 elf comparison
-------------------
 338 randomly picked binaries from binutils,coreutils,findutils
33.76% of stripped procedures are not found correctly by IDA
- For O0 the percetage is 29.99%
- For O1 the percetage is 34.67%
- For O2 the percetage is 39.93%
- For O3 the percetage is 53.84%

amd64/aarch64 comparison
------------------------
95 randomly picked binaries from coreutils tested with IDA, angr and BAP. Findings are:
- IDA
	- amd64: 46.18% of stripped procedures are not found correctly
	- aarch64: 55.42% of stripped procedures are not found correctly
- angr
	- amd64: 3.74% of stripped procedures are not found correctly
	- aarch64: 12.14% of stripped procedures are not found correctly
- BAP
	- amd64: XXXX% of stripped procedures are not found correctly
	- aarch64: XXXX% of stripped procedures are not found correctly