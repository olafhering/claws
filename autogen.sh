#!/bin/sh
# Copyright 1999-2014 the Claws Mail team.
# This file is part of Claws Mail package, and distributed under the
# terms of the General Public License version 3 (or later).
# See COPYING file for license details.

bisonver=`bison --version`

if [ "$bisonver" = "" ]; then
	echo Bison is needed to compile Claws Mail git
	exit 1
fi

flexver=`${LEX:-flex} --version | cut -d' ' -f2 | \
	awk -F. '{ print ($1 * 10000) + ($2 * 100) + $3 }'`

if [ ${flexver:-0} -lt 20531 ]; then
	echo Flex 2.5.31 or greater is needed to compile Claws Mail git
	exit 1
fi

case `uname` in
	Darwin*)
		if [ "`glibtoolize --version`" = "" ]; then
			echo MacOS requires glibtool from either Macport or brew
			exit 1
		fi
		LIBTOOL="glibtoolize --force --copy"
		;;
	*)
		LIBTOOL="libtoolize --force --copy"
		;;
esac

${LIBTOOL} \
  && autopoint -f \
  && aclocal -I m4 \
  && autoconf \
  && autoheader \
  && automake --add-missing --foreign --copy
if test -z "$NOCONFIGURE"; then
exec ./configure --enable-maintainer-mode "$@"
fi   
