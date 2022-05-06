#!/bin/bash
set -ex
case "$1" in
	-m)
		make -j $(getconf _NPROCESSORS_ONLN) >/dev/null
		wait
	;;
	-c)
	env \
		CFLAGS='-O2 -g -Wall -Wno-deprecated-declarations' \
		CXXFLAGS='-O2 -g -Wall -Wno-deprecated-declarations' \
	bash autogen.sh	\
		--prefix=/dev/shm/$PPID \
		--disable-nls
	;;
	-t)
	find * ../{glib,gtk}.git -name '*.[ch]' | ctags -L -
	;;
esac