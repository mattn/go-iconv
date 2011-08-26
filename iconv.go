//
// iconv.go
//
package iconv

/*
#ifdef _WIN32
#include <windows.h>
#include <errno.h>

typedef int iconv_t;

static HMODULE iconv_lib;
static HMODULE msvcrt_lib;
static size_t (*_iconv) (iconv_t cd, const char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static iconv_t (*_iconv_open) (const char *tocode, const char *fromcode);
static int (*_iconv_close) (iconv_t cd);
static int (*_iconvctl) (iconv_t cd, int request, void *argument);
static int* (*_iconv_errno) (void);

#define ICONV_E2BIG  7
#define ICONV_EINVAL 22
#define ICONV_EILSEQ 42

size_t iconv(iconv_t cd, const char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft) {
  return _iconv(cd, inbuf, inbytesleft, outbuf, outbytesleft);
}

iconv_t iconv_open(const char *tocode, const char *fromcode) {
  return _iconv_open(tocode, fromcode);
}

int iconv_close(iconv_t cd) {
  return _iconv_close(cd);
}

int iconvctl(iconv_t cd, int request, void *argument) {
  return _iconvctl(cd, request, argument);
}

int iconv_errno(void) {
  int *p = _iconv_errno();
  return p ? *p : 0;
}

int _iconv_init() {
  char* iconv_dll = getenv("ICONV_DLL");
  if (iconv_dll)
    iconv_lib = LoadLibrary(iconv_dll);
  if (iconv_lib == 0)
    iconv_lib = LoadLibrary("iconv.dll");
  if (iconv_lib == 0)
    iconv_lib = LoadLibrary("libiconv.dll");
  msvcrt_lib = LoadLibrary("msvcrt.dll");
  if (iconv_lib == 0 || msvcrt_lib == 0) return -1;
  _iconv = (void *) GetProcAddress(iconv_lib, "libiconv");
  _iconv_open = (void *) GetProcAddress(iconv_lib, "libiconv_open");
  _iconv_close = (void *) GetProcAddress(iconv_lib, "libiconv_close");
  _iconvctl = (void *) GetProcAddress(iconv_lib, "libiconvctl");
  _iconv_errno = (void *) GetProcAddress(msvcrt_lib, "_errno");
  if (_iconv == NULL || _iconv_open == NULL || _iconv_close == NULL
    || _iconvctl == NULL || _iconv_errno == NULL) return -2;
  return 0;
}
#else
#include <iconv.h>
#include <errno.h>
#include <stdlib.h>
#define ICONV_E2BIG  E2BIG
#define ICONV_EINVAL EINVAL
#define ICONV_EILSEQ EILSEQ
#define ICONV_ERRNO  errno

int _iconv_init() {
  return 0;
}
#endif
*/
import "C"

import (
	"bytes"
	"os"
	"sync"
	"unsafe"
)

var EINVAL = os.Errno(int(C.ICONV_EINVAL))
var EILSEQ = os.Errno(int(C.ICONV_EILSEQ))
var E2BIG = os.Errno(int(C.ICONV_E2BIG))

type Iconv struct {
	pointer C.iconv_t
}

var onceSetupIconv sync.Once

func setupIconv() {
	if C._iconv_init() != C.int(0) {
		panic("can't initialize iconv")
	}
}

func Open(tocode string, fromcode string) (*Iconv, os.Error) {
	onceSetupIconv.Do(setupIconv)

	pt := C.CString(tocode)
	pf := C.CString(fromcode)
	defer C.free(unsafe.Pointer(pt))
	defer C.free(unsafe.Pointer(pf))
	ret, err := C.iconv_open(pt, pf)
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
		_, err := C.iconv(cd.pointer,
			(**C.char)(unsafe.Pointer(&inptr)), &inbytes,
			(**C.char)(unsafe.Pointer(&outptr)), &outbytes)
		buf.Write(outbuf[:len(outbuf)-int(outbytes)])
		if err != nil && err != E2BIG {
			return buf.String(), err
		}
	}

	return buf.String(), nil
}

func (cd *Iconv) ConvBytes(inbuf []byte) (result []byte, err os.Error) {
	var buf bytes.Buffer

	if len(inbuf) == 0 {
		return []byte{}, nil
	}

	outbuf := make([]byte, len(inbuf))
	inbytes := C.size_t(len(inbuf))
	inptr := &inbuf[0]

	for inbytes > 0 {
		outbytes := C.size_t(len(outbuf))
		outptr := &outbuf[0]
		_, err := C.iconv(cd.pointer,
			(**C.char)(unsafe.Pointer(&inptr)), &inbytes,
			(**C.char)(unsafe.Pointer(&outptr)), &outbytes)
		buf.Write(outbuf[:len(outbuf)-int(outbytes)])
		if err != nil && err != E2BIG {
			return buf.Bytes(), err
		}
	}

	return buf.Bytes(), nil
}
