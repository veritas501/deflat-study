OLLVM=~/src/ollvm_build/bin/clang
all:
	gcc chk.c -o x64_none
	${OLLVM} chk.c -o x64_fla -mllvm -fla
	${OLLVM} chk.c -o x64_fla_split -mllvm -fla -mllvm -split
	${OLLVM} chk.c -o x64_fla_sub -mllvm -fla -mllvm -sub
	${OLLVM} chk.c -o x64_fla_bcf -mllvm -fla -mllvm -bcf
	${OLLVM} chk.c -o x64_fla_O3 -mllvm -fla -O3
	${OLLVM} chk.c -o x64_fla_split_O3 -mllvm -fla -mllvm -split -O3
	${OLLVM} chk.c -o x64_fla_sub_O3 -mllvm -fla -mllvm -sub -O3
	${OLLVM} chk.c -o x64_fla_bcf_O3 -mllvm -fla -mllvm -bcf -O3

clean_deflat:
	rm -rf deflat_*