BAP Installation Steps:
=======================

v0.9.9:
-------
My machine is running Ubuntu 14.04 LTS x64 with 2 GB RAM (BAP installation needs at least 2 GB to run successfully).
Run the following commands in order to install it successfully:
- wget https://raw.github.com/ocaml/opam/master/shell/opam_installer.sh -O - | sh -s /usr/local/bin
- opam init --comp=4.02.3
- opam repo add bap git://github.com/BinaryAnalysisPlatform/opam-repository
- sudo apt-get install ocaml-native-compilers
- eval \`opam config env\`
- opam depext --install bap

v1.0.0:
-------
My machine is running Ubuntu 16.04 x64 with 2 GB RAM (BAP installation needs at least 2 GB to run successfully).
- wget https://raw.github.com/ocaml/opam/master/shell/opam_installer.sh -O - | sh -s /usr/local/bin
- opam init --comp=4.02.3
- opam repo add bap git://github.com/BinaryAnalysisPlatform/opam-repository
- sudo apt-get install ocaml-native-compilers
- opam switch 4.02.3
- eval \`opam config env\`
- opam install bap.1.0.0

Tests Instructions:
===================
In order to reproduce the results of this research, you should use the following scripts:
- func_bounds.py \<executable_path\>
	- This script extracts all function names and boundaries for unstripped binaries using objdump and DWARF info inside the ELF
- ida_compare_all_binaries.py \<i386/amd64/aarch64\>
	- This script comapares all function bounds of stripped and unstripped binaries version under bin_repo/<arch> using IDA.
	- It runs multiple instances of IDA, each instance for a different binary. So beware of filters which catches too many files.
	- To filter specific files for comparison, adjust BINARIES_NAME_PATTERN regexp (default is "^.*")
	- Remeber to adjust IDA path on your machine before use, and adjust it when shifting from x86 to x64 (idaq.exe to idaq64.exe)
- angr_compare_all_binaries.py \<i386/amd64/aarch64\>
	- This script comapares all function bounds of stripped and unstripped binaries version under bin_repo/<arch> using angr framework.
	- To filter specific files for comparison, adjust BINARIES_NAME_PATTERN regexp (default is "^.*")
- bap_compare_all_binaries.py \<i386/amd64/aarch64\>
	- This script comapares all function bounds of stripped and unstripped binaries version under bin_repo/<arch> using BAP framework.
	- To filter specific files for comparison, adjust BINARIES_NAME_PATTERN regexp (default is "^.*")

General Findings:
==================
i386 IDA Comparison
------------------------
338 randomly picked binaries from binutils,coreutils,findutils
- 33.18% of stripped procedures are not found correctly by IDA
	- For O0 the percetage is 30.94%
	- For O1 the percetage is 33.36%
	- For O2 the percetage is 35.23%
	- For O3 the percetage is 39.99%

amd64/aarch64 Comparison
------------------------
95 randomly picked binaries from coreutils tested with IDA, angr and BAP. Findings are:
- IDA
	- amd64: 37.13% of stripped procedures are not found correctly
	- aarch64: 40.54% of stripped procedures are not found correctly
- angr
	- amd64: 3.74% of stripped procedures are not found correctly
	- aarch64: 12.14% of stripped procedures are not found correctly
- BAP
	- v0.9.9
		- amd64: 32.64% of stripped procedures are not found correctly
		- aarch64: 99.67% of stripped procedures are not found correctly
	- v1.0.0
		- amd64: 23.22% of stripped procedures are not found correctly
		- aarch64: Failed with the message: "byteweight.error> no signatures for specified compiler and architecture"