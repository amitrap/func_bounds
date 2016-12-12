BAP Installation Steps:
=======================
My machine is running Ubuntu 14.04 x64 with 2 GB RAM (BAP installation needs at least 2 GB to run successfully).
Run the following commands in order to install it successfully:
- wget https://raw.github.com/ocaml/opam/master/shell/opam_installer.sh -O - | sh -s /usr/local/bin
- opam init --comp=4.02.3
- opam repo add bap git://github.com/BinaryAnalysisPlatform/opam-repository
- eval `opam config env`
- sudo apt-get install ocaml-native-compilers
- opam depext --install bap
- bap-byteweight update

Tests Instructions:
===================
In order to reproduce the results of this research, you should use the following scripts:
- func_bounds.py [executable_path]
	- This script extracts all function names and boundaries for unstripped binaries using objdump and DWARF info inside the ELF
- ida_compare_all_binaries.py [arch: i386/amd64/aarch64]
	- This script comapares all function bounds of stripped and unstripped binaries version under bin_repo/<arch> using IDA.
	- It runs multiple instances of IDA, each instance for a different binary. So beware of filters which catches too many files.
	- To filter specific files for comparison, adjust BINARIES_NAME_PATTERN regexp (default is "^.*")
	- Remeber to adjust IDA path on your machine before use, and adjust it when shifting from x86 to x64 (idaq.exe to idaq64.exe)
- angr_compare_all_binaries.py [arch: i386/amd64/aarch64]
	- This script comapares all function bounds of stripped and unstripped binaries version under bin_repo/<arch> using angr.io framework.
	- To filter specific files for comparison, adjust BINARIES_NAME_PATTERN regexp (default is "^.*")
- bap_compare_all_binaries.py [arch: i386/amd64/aarch64]
	- This script comapares all function bounds of stripped and unstripped binaries version under bin_repo/<arch> using BAP framework.
	- To filter specific files for comparison, adjust BINARIES_NAME_PATTERN regexp (default is "^.*")

General Findings:
==================
i386 IDA Comparison
------------------------
338 randomly picked binaries from binutils,coreutils,findutils
33.76% of stripped procedures are not found correctly by IDA
- For O0 the percetage is 29.99%
- For O1 the percetage is 34.67%
- For O2 the percetage is 39.93%
- For O3 the percetage is 53.84%

amd64/aarch64 Comparison
------------------------
95 randomly picked binaries from coreutils tested with IDA, angr and BAP. Findings are:
- IDA
	- amd64: 46.18% of stripped procedures are not found correctly
	- aarch64: 55.42% of stripped procedures are not found correctly
- angr
	- amd64: 3.74% of stripped procedures are not found correctly
	- aarch64: 12.14% of stripped procedures are not found correctly
- BAP
	- amd64: 32.64% of stripped procedures are not found correctly
	- aarch64: 99.67% of stripped procedures are not found correctly