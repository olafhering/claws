# vim: syntax=spec

%bcond_without claws_sm
%bcond_without claws_ipv6
%bcond_without claws_gnutls
%bcond_without claws_enchant
%bcond_without claws_crashdialog
%bcond_without claws_compface
%bcond_without claws_pthread
%bcond_without claws_startup_notification
%bcond_without claws_dbus
%bcond_without claws_ldap
%bcond_with    claws_jpilot
%bcond_without claws_networkmanager
%bcond_without claws_libetpan
%bcond_without claws_svg
%bcond_without claws_valgrind
#
%bcond_without claws_plugin_acpi_notifier
%bcond_without claws_plugin_address_keeper
%bcond_without claws_plugin_archive
%bcond_without claws_plugin_att_remover
%bcond_without claws_plugin_attachwarner
%bcond_without claws_plugin_bogofilter
%bcond_without claws_plugin_bsfilter
%bcond_without claws_plugin_clamd
%bcond_without claws_plugin_dillo
%bcond_without claws_plugin_fancy
%bcond_without claws_plugin_fetchinfo
%bcond_without claws_plugin_gdata
%bcond_without claws_plugin_libravatar
%bcond_without claws_plugin_litehtml_viewer
%bcond_without claws_plugin_mailmbox
%bcond_without claws_plugin_managesieve
%bcond_without claws_plugin_newmail
%bcond_without claws_plugin_notification
%bcond_without claws_plugin_pdf_viewer
%bcond_without claws_plugin_perl
%bcond_with    claws_plugin_python
%bcond_without claws_plugin_pgpcore
%bcond_without claws_plugin_pgpmime
%bcond_without claws_plugin_pgpinline
%bcond_without claws_plugin_rssyl
%bcond_without claws_plugin_smime
%bcond_without claws_plugin_spamassassin
%bcond_without claws_plugin_spam_report
%bcond_without claws_plugin_tnef_parse
%bcond_without claws_plugin_vcalendar
%bcond_with    claws_plugin_demo
#
%global  _buildshell /bin/bash
# PACKAGE_TARNAME
Name:           claws-mail-olh
Version:        0
Release:        0
License:        GPL-3.0+
# PACKAGE_NAME
Summary:        Claws Mail (olh)
Conflicts:      %name-debuginfo < %version-%release
Conflicts:      %name-debugsource < %version-%release
URL:            https://gitlab.com/olafhering/claws/-/compare/3.21.0...olh-3.21.0
#
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  bison
BuildRequires:  flex
BuildRequires:  update-desktop-files
#
BuildRequires:  gtk2-tools
BuildRequires:  pkg-config
BuildRequires:  gawk
BuildRequires:  gettext
BuildRequires:  pkgconfig(glib-2.0) >= 2.50
BuildRequires:  pkgconfig(gmodule-2.0) >= 2.50
BuildRequires:  pkgconfig(gobject-2.0) >= 2.50
BuildRequires:  pkgconfig(gthread-2.0) >= 2.50
BuildRequires:  pkgconfig(gdk-pixbuf-2.0) >= 2.26
BuildRequires:  pkgconfig(nettle)
%if %{with claws_sm}
BuildRequires:  pkgconfig(sm)
%endif
%if %{with claws_gnutls}
BuildRequires:  pkgconfig(gnutls) >= 2.2
%endif
BuildRequires:  pkgconfig(gtk+-2.0) >= 2.24
%if %{with claws_enchant}
BuildRequires:  pkgconfig(enchant)
Requires:       myspell-de_DE
%endif
%if %{with claws_compface}
BuildRequires:  compface-devel
%endif
%if %{with claws_startup_notification}
BuildRequires:  pkgconfig(libstartup-notification-1.0) >= 0.5
%endif
%if %{with claws_dbus}
BuildRequires:  pkgconfig(dbus-1) >= 0.60
BuildRequires:  pkgconfig(dbus-glib-1) >= 0.60
%endif
%if %{with claws_ldap}
BuildRequires:  openldap2-devel
%endif
%if %{with claws_jpilot}
BuildRequires:  pkgconfig(pilot-link)
%endif
%if %{with claws_networkmanager}
BuildRequires:  pkgconfig(libnm)
%endif
%if %{with claws_libetpan}
BuildRequires:  pkgconfig(libetpan)
%endif
%if %{with claws_svg}
BuildRequires:  pkgconfig(librsvg-2.0) >= 2.39.0
BuildRequires:  pkgconfig(cairo) >= 1.0.0
%endif
%if %{with claws_valgrind}
BuildRequires:  pkgconfig(valgrind) >= 2.4.0
%endif
#
%if %{with claws_plugin_archive}
BuildRequires:  pkgconfig(libarchive)
%endif
%if %{with claws_plugin_fancy}
BuildRequires:  pkgconfig(webkit-1.0) >= 1.10.0
BuildRequires:  pkgconfig(libcurl)
%endif
%if %{with claws_plugin_gdata}
BuildRequires:  pkgconfig(libgdata) >= 0.6.4
%endif
%if %{with claws_plugin_libravatar}
BuildRequires:  pkgconfig(libcurl)
%endif
%if %{with claws_plugin_litehtml_viewer}
BuildRequires:  gcc-c++
BuildRequires:  pkgconfig(cairo)
BuildRequires:  pkgconfig(fontconfig)
BuildRequires:  pkgconfig(gumbo)
%endif
%if %{with claws_plugin_notification}
#hotkeys
BuildRequires:  pkgconfig(gio-2.0) >= 2.15.6
BuildRequires:  pkgconfig(gio-unix-2.0) >= 2.15.6
#unity
#uildRequires:  pkgconfig(unity)
#uildRequires:  pkgconfig(messaging-menu)
#libnotify
BuildRequires:  pkgconfig(libnotify) >= 0.4.3
#libcanberra-gtk
BuildRequires:  pkgconfig(libcanberra-gtk) >= 0.6
%endif
%if %{with claws_plugin_pdf_viewer}
BuildRequires:  pkgconfig(poppler-glib) >= 0.12.0
%endif
%if %{with claws_plugin_perl}
%{?libperl_requires}
%endif
%if %{with claws_plugin_python}
BuildRequires:  pkgconfig(python2)
BuildRequires:  pkgconfig(pygtk-2.0) >= 2.10.3
%endif
%if %{with claws_plugin_pgpcore}
BuildRequires:  libgpgme-devel
%endif
%if %{with claws_plugin_pgpmime}
BuildRequires:  libgpgme-devel
%endif
%if %{with claws_plugin_pgpinline}
BuildRequires:  libgpgme-devel
%endif
%if %{with claws_plugin_rssyl}
BuildRequires:  pkgconfig(expat)
BuildRequires:  pkgconfig(libcurl)
%endif
%if %{with claws_plugin_smime}
BuildRequires:  libgpgme-devel
%endif
%if %{with claws_plugin_spam_report}
BuildRequires:  pkgconfig(libcurl)
%endif
%if %{with claws_plugin_tnef_parse}
BuildRequires:  libytnef-devel
%endif
%if %{with claws_plugin_vcalendar}
BuildRequires:  pkgconfig(libcurl)
BuildRequires:  pkgconfig(libical) >= 2.0
%{?libperl_requires}
%endif

%description
Claws Mail is a email client and news reader.

%prep
rm -rf %_builddir/%name-%version
mv %_sourcedir/%name-%version %_builddir/%name-%version
%setup -c -T -D
%autopatch -p1

%build
name='%name'
tee .env.%name-%version-%release.txt <<_EOF_
PACKAGE_NAME="Claws Mail (${name#claws-mail-})"
_EOF_
. .env.%name-%version-%release.txt
sed -i~ "
s|^AC_INIT.*|AC_INIT([${PACKAGE_NAME}],[%version],[],[%name],[%url])|
" configure.ac
diff -u "$_"~ "$_" || :
echo '%version' > VERSION_UI
echo 'echo 8.8.8.8' > version
env NOCONFIGURE=NOCONFIGURE ./autogen.sh
export DOCBOOK2HTML=/bin/false
export DOCBOOK2TXT=/bin/false
export DOCBOOK2PS=/bin/false
export DOCBOOK2PDF=/bin/false
%if %{with claws_crashdialog}
export enable_crash_dialog=/usr/bin/gdb
%endif

CFLAGS='%optflags -Wno-deprecated-declarations -std=gnu99'
%configure --help
%configure \
	--enable-maintainer-mode \
	--disable-static \
	--disable-manual \
	--disable-libsm \
	--disable-ipv6 \
	--disable-gnutls \
	--disable-enchant \
	--disable-crash-dialog \
	--disable-generic-umpc \
	--disable-compface \
	--disable-pthread \
	--disable-startup-notification \
	--disable-dbus \
	--disable-ldap \
	--disable-jpilot \
	--disable-networkmanager \
	--disable-libetpan \
	--disable-valgrind \
	--disable-alternate-addressbook \
	--disable-svg \
	\
	--disable-acpi_notifier-plugin \
	--disable-address_keeper-plugin \
	--disable-archive-plugin \
	--disable-att_remover-plugin \
	--disable-attachwarner-plugin \
	--disable-bogofilter-plugin \
	--disable-bsfilter-plugin \
	--disable-clamd-plugin \
	--disable-dillo-plugin \
	--disable-fancy-plugin \
	--disable-fetchinfo-plugin \
	--disable-gdata-plugin \
	--disable-libravatar-plugin \
	--disable-litehtml_viewer-plugin \
	--disable-mailmbox-plugin \
	--disable-managesieve-plugin \
	--disable-newmail-plugin \
	--disable-notification-plugin \
	--disable-pdf_viewer-plugin \
	--disable-perl-plugin \
	--disable-python-plugin \
	--disable-pgpcore-plugin \
	--disable-pgpmime-plugin \
	--disable-pgpinline-plugin \
	--disable-rssyl-plugin \
	--disable-smime-plugin \
	--disable-spamassassin-plugin \
	--disable-spam_report-plugin \
	--disable-tnef_parse-plugin \
	--disable-vcalendar-plugin \
	--disable-demo-plugin \
	\
%if %{with claws_sm}
	--enable-libsm \
%endif
%if %{with claws_ipv6}
	--enable-ipv6 \
%endif
%if %{with claws_gnutls}
	--enable-gnutls \
%endif
%if %{with claws_enchant}
	--enable-enchant \
%endif
%if %{with claws_crashdialog}
	--enable-crash-dialog \
%endif
%if %{with claws_compface}
	--enable-compface \
%endif
%if %{with claws_pthread}
	--enable-pthread \
%endif
%if %{with claws_startup_notification}
	--enable-startup-notification \
%endif
%if %{with claws_dbus}
	--enable-dbus \
%endif
%if %{with claws_ldap}
	--enable-ldap \
%endif
%if %{with claws_jpilot}
	--enable-jpilot \
%endif
%if %{with claws_networkmanager}
	--enable-networkmanager \
%endif
%if %{with claws_libetpan}
	--enable-libetpan \
%endif
%if %{with claws_svg}
	--enable-svg \
%endif
%if %{with claws_valgrind}
	--enable-valgrind \
%endif
%if %{with claws_plugin_acpi_notifier}
	--enable-acpi_notifier-plugin \
%endif
%if %{with claws_plugin_address_keeper}
	--enable-address_keeper-plugin \
%endif
%if %{with claws_plugin_archive}
	--enable-archive-plugin \
%endif
%if %{with claws_plugin_att_remover}
	--enable-att_remover-plugin \
%endif
%if %{with claws_plugin_attachwarner}
	--enable-attachwarner-plugin \
%endif
%if %{with claws_plugin_bogofilter}
	--enable-bogofilter-plugin \
%endif
%if %{with claws_plugin_bsfilter}
	--enable-bsfilter-plugin \
%endif
%if %{with claws_plugin_clamd}
	--enable-clamd-plugin \
%endif
%if %{with claws_plugin_dillo}
	--enable-dillo-plugin \
%endif
%if %{with claws_plugin_fancy}
	--enable-fancy-plugin \
%endif
%if %{with claws_plugin_fetchinfo}
	--enable-fetchinfo-plugin \
%endif
%if %{with claws_plugin_gdata}
	--enable-gdata-plugin \
%endif
%if %{with claws_plugin_libravatar}
	--enable-libravatar-plugin \
%endif
%if %{with claws_plugin_litehtml_viewer}
	--enable-litehtml_viewer-plugin \
%endif
%if %{with claws_plugin_mailmbox}
	--enable-mailmbox-plugin \
%endif
%if %{with claws_plugin_managesieve}
	--enable-managesieve-plugin \
%endif
%if %{with claws_plugin_newmail}
	--enable-newmail-plugin \
%endif
%if %{with claws_plugin_notification}
	--enable-notification-plugin \
%endif
%if %{with claws_plugin_pdf_viewer}
	--enable-pdf_viewer-plugin \
%endif
%if %{with claws_plugin_perl}
	--enable-perl-plugin \
%endif
%if %{with claws_plugin_python}
	--enable-python-plugin \
%endif
%if %{with claws_plugin_pgpcore}
	--enable-pgpcore-plugin \
%endif
%if %{with claws_plugin_pgpmime}
	--enable-pgpmime-plugin \
%endif
%if %{with claws_plugin_pgpinline}
	--enable-pgpinline-plugin \
%endif
%if %{with claws_plugin_rssyl}
	--enable-rssyl-plugin \
%endif
%if %{with claws_plugin_smime}
	--enable-smime-plugin \
%endif
%if %{with claws_plugin_spamassassin}
	--enable-spamassassin-plugin \
%endif
%if %{with claws_plugin_spam_report}
	--enable-spam_report-plugin \
%endif
%if %{with claws_plugin_tnef_parse}
	--enable-tnef_parse-plugin \
%endif
%if %{with claws_plugin_vcalendar}
	--enable-vcalendar-plugin \
%endif
%if %{with claws_plugin_demo}
	--enable-demo-plugin \
%endif
	--with-config-dir=".%name"
diff -u src/common/version.h{.in,} && exit 1
%make_build CFLAGS='%optflags -Wno-deprecated-declarations -std=gnu99 -Og -ggdb3 -gdwarf-4 -fno-omit-frame-pointer -fsanitize=address,undefined'

%install
. .env.%name-%version-%release.txt
%makeinstall
find %buildroot -ls
find %buildroot -name "*.la" -print -delete
find %buildroot -name RELEASE_NOTES -print -delete
rm -rf %buildroot%_includedir %buildroot%_libdir/pkgconfig
mv -v %buildroot%_bindir/{claws-mail,%name}
mv -v %buildroot%_mandir/man1/{claws-mail,%name}.1
mkdir -vp %buildroot%_datadir/xfce4/helpers/
pushd "$_" > /dev/null
tee %name.desktop <<_EOF_
[Desktop Entry]
Version=1.0
Icon=%name
Type=X-XFCE-Helper
Name=${PACKAGE_NAME}
StartupNotify=true
X-XFCE-Binaries=%name
X-XFCE-Category=MailReader
X-XFCE-Commands=%%B;
X-XFCE-CommandsWithParameter=/usr/lib/xfce4/xfce4-compose-mail sylpheed %%B "mailto:%%s";
_EOF_
popd > /dev/null
sed "
s|^Name=Claws Mail$|Name=${PACKAGE_NAME}|
s|^Exec=claws-mail|Exec=%name|
s|^Icon=claws-mail|Icon=%name|
/^X-Info/d
" %buildroot%_datadir/applications/claws-mail.desktop > %buildroot%_datadir/applications/%name.desktop 
diff -u %buildroot%_datadir/applications/claws-mail.desktop %buildroot%_datadir/applications/%name.desktop && exit 1
rm -fv %buildroot%_datadir/applications/claws-mail.desktop
%suse_update_desktop_file %name
install -p -m 444 -D claws-mail-128x128.png %buildroot%_datadir/pixmaps/%name.png
%find_lang %name %{?no_lang_C}

%files -f %name.lang
%license COPYING
%_bindir/*
%_datadir/applications/*
%_datadir/icons/*
%_datadir/pixmaps/*
%_datadir/xfce4
%_libdir/%name
%_mandir/man1/*

%changelog

