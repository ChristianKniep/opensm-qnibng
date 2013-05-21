
INCLUDES = -I$(srcdir)/../include \
	   -I$(includedir)/infiniband

lib_LTLIBRARIES = libqnibng.la

if DEBUG
DBGFLAGS = -ggdb -D_DEBUG_
else
DBGFLAGS = -g
endif

libqnibng_la_CFLAGS = -Wall $(DBGFLAGS) -D_XOPEN_SOURCE=600 -D_BSD_SOURCE=1

if HAVE_LD_VERSION_SCRIPT
    libqnibng_version_script = -Wl,--version-script=$(srcdir)/libqnibng.map
else
    libqnibng_version_script =
endif

qnibng_api_version=$(shell grep LIBVERSION= $(srcdir)/libqnibng.ver | sed 's/LIBVERSION=//')

libqnibng_la_SOURCES = src/qnibng.c
libqnibng_la_LDFLAGS = -version-info $(qnibng_api_version) \
	 -export-dynamic $(libqnibng_version_script)
libqnibng_la_LIBADD = -L../complib $(OSMV_LDADD) -losmcomp
libqnibng_la_DEPENDENCIES = $(srcdir)/libqnibng.map

libqnibngincludedir = $(includedir)/infiniband/complib

libqnibnginclude_HEADERS =

# headers are distributed as part of the include dir
EXTRA_DIST = $(srcdir)/libqnibng.map $(srcdir)/libqnibng.ver
