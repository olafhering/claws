#!/bin/bash
set -ex
renice -n 11 -p "$$"
ionice --class 3 -p "$$"
case "$1" in
	-m)
		make -j $(getconf _NPROCESSORS_ONLN) >/dev/null
		wait
	;;
	-c)
	shift
	env \
		CFLAGS='-O2 -g -Wall -Wno-deprecated-declarations' \
		CXXFLAGS='-O2 -g -Wall -Wno-deprecated-declarations -Wno-reorder -Wno-sign-compare -Wno-switch' \
	bash autogen.sh	\
		--prefix=/dev/shm/$PPID \
		"$@"
	;;
	-t)
	find * ../{gdk-pixbuf,glib,gnutls,gtk,libetpan}.git -name '*.[ch]' | ctags -L -
	;;
esac