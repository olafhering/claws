#!/bin/bash
set -ex
renice -n 11 -p "$$"
ionice --class 3 -p "$$" || : $?
declare -i cpus=0
test "${cpus}" -lt 1 && cpus=$(getconf _NPROCESSORS_ONLN || :)
test "${cpus}" -lt 1 && cpus=$(getconf  NPROCESSORS_ONLN || :)
test "${cpus}" -lt 1 && cpus=1
do_it() {
	local arg=$1
	case "${arg}" in
		-m)
			gmake -j "${cpus}" >/dev/null
			wait
		;;
		-c)
		shift
		if test $# -gt 0
		then
			args=("$@")
		else
			args=('--disable-nls')
		fi
		for x in /usr/local/bin/autoconf-*
		do
			test -x "$x" || continue
			AUTOCONF_VERSION=${x##*/}
			AUTOCONF_VERSION=${AUTOCONF_VERSION#autoconf-}
		done
		for x in /usr/local/bin/automake-*
		do
			test -x "$x" || continue
			AUTOMAKE_VERSION=${x##*/}
			AUTOMAKE_VERSION=${AUTOMAKE_VERSION#automake-}
		done
		env \
			AUTOCONF_VERSION=${AUTOCONF_VERSION} \
			AUTOMAKE_VERSION=${AUTOMAKE_VERSION} \
			CFLAGS='-O2 -g -Wall -Wno-deprecated-declarations' \
			CXXFLAGS='-O2 -g -Wall -Wno-deprecated-declarations -Wno-reorder -Wno-sign-compare -Wno-switch' \
		bash autogen.sh	\
			"${args[@]}"
	#		--prefix=/dev/shm/$PPID \
		;;
		-t)
		find * ../{gdk-pixbuf,glib,gnutls,gtk,libetpan}.git -name '*.[ch]' | ctags -L -
		;;
	esac
}
for arg in $@
do
	do_it "${arg}"
done
