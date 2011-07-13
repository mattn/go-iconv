//
// iconv.go
//
package iconv

/*
#ifdef _WIN32
#include <windows.h>

size_t (*iconv) (iconv_t cd, const char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
iconv_t (*iconv_open) (const char *tocode, const char *fromcode);
int (*iconv_close) (iconv_t cd);
int (*iconvctl) (iconv_t cd, int request, void *argument);
int* (*iconv_errno) (void);

int _iconv_init() {
  HMODULE hIconvDLL, hMsvcrtDLL;
  hIconvDLL = LoadLibrary("iconv.dll");
  if (hIconvDLL == 0)
    hIconvDLL = LoadLibrary("libiconv.dll");
  hMsvcrtDLL = LoadLibrary("msvcrt.dll");
  if (hIconvDLL != 0 && hMsvcrtDLL != 0) return -1;
  iconv = (void *) GetProcAddress(hIconvDLL, "libiconv");
  iconv_open = (void *) GetProcAddress(hIconvDLL, "libiconv_open");
  iconv_close = (void *) GetProcAddress(hIconvDLL, "libiconv_close");
  iconvctl = (void *) GetProcAddress(hIconvDLL, "libiconvctl");
  iconv_errno = (void *) GetProcAddress(hMsvcrtDLL, "_errno");
  if (iconv == NULL || iconv_open == NULL || iconv_close == NULL
    || iconvctl == NULL || iconv_errno == NULL) return -2;
  return 0;
}
#else
#include <iconv.h>
#include <errno.h>

int _iconv_init() {
  return 0;
}
#endif
*/
import "C"

import (
	"os"
	"unsafe"
	"bytes"
)

var EILSEQ = os.Errno(int(C.EILSEQ))
var E2BIG = os.Errno(int(C.E2BIG))

func init() {
	if (C._iconv_init() != C.int(0)) {
		panic("can't initialize iconv");
	}
}

type Iconv struct {
	pointer C.iconv_t
}

func Open(tocode string, fromcode string) (*Iconv, os.Error) {
	ret, err := C.iconv_open(C.CString(tocode), C.CString(fromcode))
	if err != nil {
		return nil, err
	}
	return &Iconv{ret}, nil
}

func (cd *Iconv) Close() os.Error {
	_, err := C.iconv_close(cd.pointer)
	return err
}

func (cd *Iconv) Conv(input string) (result string, err os.Error) {
	var buf bytes.Buffer

	if len(input) == 0 {
		return "", nil
	}

	inbuf := []byte(input)
	outbuf := make([]byte, len(inbuf))
	inbytes := C.size_t(len(inbuf))
	inptr := &inbuf[0]

	for inbytes > 0 {
		outbytes := C.size_t(len(outbuf))
		outptr := &outbuf[0]
		_, err = C.iconv(cd.pointer,
			(**C.char)(unsafe.Pointer(&inptr)), &inbytes,
			(**C.char)(unsafe.Pointer(&outptr)), &outbytes)
		buf.Write(outbuf[:len(outbuf)-int(outbytes)])
		if err != nil && err != E2BIG {
			return buf.String(), err
		}
	}

	return buf.String(), nil
}
