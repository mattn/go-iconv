#
#
#

include $(GOROOT)/src/Make.inc

TARG=github.com/mattn/go-iconv
CGOFILES=iconv.go

include $(GOROOT)/src/Make.pkg
