#! /bin/bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Automatically reindent one .c or .h source file, writing the
# modified file over the original.

show_usage() {
    1>&2 echo "usage: `basename $0` <C-source-file-name> [ linux-kernel-style | clang-style ] [ any other parameters required by the selected style ... ]" 
}

if [ $# -lt 2 ]
then
    show_usage
    exit 1
fi

F="$1"
STYLE="$2"

case "${STYLE}" in
    linux-kernel-style)
	LINUX_KERNEL_ROOT_DIR="$3"
	LINUX_INDENT_SCRIPT="${LINUX_KERNEL_ROOT_DIR}/scripts/Lindent"
	if [ ! -e ${LINUX_INDENT_SCRIPT} ]
	then
	    1>&2 echo "Expected to find an executable file here, but no such file or not executable: ${LINUX_INDENT_SCRIPT}"
	    exit 1
	fi
	echo "${LINUX_INDENT_SCRIPT} ${F} ..."
	${LINUX_INDENT_SCRIPT} "${F}"
	;;
    clang-style)
	# -i causes clang-format to edit the file in-place, i.e. to
	# -overwrite the original file.
	echo 'clang-format -i -style="{BasedOnStyle: llvm, IndentWidth: 4, SortIncludes: false}"' "$F" ...
	clang-format -i -style="{BasedOnStyle: llvm, IndentWidth: 4, SortIncludes: false}" "$F"
	;;
    *)
	1>&2 echo "Unknown style: $STYLE"
	;;
esac
