//
// iconv.go
//
package iconv

/*
#ifdef _WIN32
#include <windows.h>
#include <errno.h>

typedef int* uintptr;
typedef int iconv_t;

static HMODULE iconv_lib = NULL;
static HMODULE msvcrt_lib = NULL;
static size_t (*iconv) (iconv_t cd, const char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft) = NULL;
static iconv_t (*iconv_open) (const char *tocode, const char *fromcode) = NULL;
static int (*iconv_close) (iconv_t cd) = NULL;
static int (*iconvctl) (iconv_t cd, int request, void *argument) = NULL;
static int* (*iconv_errno) (void) = NULL;

#define ICONV_E2BIG  7
#define ICONV_EINVAL 22
#define ICONV_EILSEQ 42

size_t
_iconv(iconv_t cd, const uintptr inbuf, size_t *inbytesleft, uintptr outbuf, size_t *outbytesleft) {
  return iconv(cd, (const char**)inbuf, inbytesleft, (char**)outbuf, outbytesleft);
}

static iconv_t
_iconv_open(const char *tocode, const char *fromcode) {
  return iconv_open(tocode, fromcode);
}

int
_iconv_close(iconv_t cd) {
  return iconv_close(cd);
}

int
_iconvctl(iconv_t cd, int request, void *argument) {
  return iconvctl(cd, request, argument);
}

int
_iconv_errno(void) {
  int *p = iconv_errno();
  return p ? *p : 0;
}

int
_iconv_init(const char* iconv_dll) {
  iconv_lib = 0;
  if (iconv_dll)
    iconv_lib = LoadLibrary(iconv_dll);
  if (iconv_lib == 0)
    iconv_lib = LoadLibrary("iconv.dll");
  if (iconv_lib == 0)
    iconv_lib = LoadLibrary("libiconv.dll");
  msvcrt_lib = LoadLibrary("msvcrt.dll");
  if (iconv_lib == 0 || msvcrt_lib == 0) return -1;
  iconv = (void *) GetProcAddress(iconv_lib, "libiconv");
  iconv_open = (void *) GetProcAddress(iconv_lib, "libiconv_open");
  iconv_close = (void *) GetProcAddress(iconv_lib, "libiconv_close");
  iconvctl = (void *) GetProcAddress(iconv_lib, "libiconvctl");
  iconv_errno = (void *) GetProcAddress(msvcrt_lib, "_errno");
  if (iconv == NULL || iconv_open == NULL || iconv_close == NULL
    || iconvctl == NULL || iconv_errno == NULL) return -2;
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

typedef int* uintptr;

int
_iconv_init(const char* iconv_dll) {
  return 0;
}

size_t
_iconv(iconv_t cd, const uintptr inbuf, size_t *inbytesleft, uintptr outbuf, size_t *outbytesleft) {
  return iconv(cd, (char**)inbuf, inbytesleft, (char**)outbuf, outbytesleft);
}

static iconv_t
_iconv_open(const char *tocode, const char *fromcode) {
  return iconv_open(tocode, fromcode);
}

int
_iconv_close(iconv_t cd) {
  return iconv_close(cd);
}

#endif

#cgo darwin LDFLAGS: -liconv
*/
import "C"

import (
	"bytes"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

var EINVAL = syscall.Errno(C.ICONV_EINVAL)
var EILSEQ = syscall.Errno(C.ICONV_EILSEQ)
var E2BIG = syscall.Errno(C.ICONV_E2BIG)

type Iconv struct {
	pointer C.iconv_t
}

var onceSetupIconv sync.Once

func setupIconv() {
	var ptr *C.char
	if iconv_dll := os.Getenv("ICONV_DLL"); len(iconv_dll) > 0 {
		ptr = C.CString(iconv_dll)
		defer C.free(unsafe.Pointer(ptr))
	}
	if C._iconv_init(ptr) != C.int(0) {
		panic("can't initialize iconv")
	}
}

func Open(tocode string, fromcode string) (*Iconv, error) {
	onceSetupIconv.Do(setupIconv)

	pt := C.CString(tocode)
	pf := C.CString(fromcode)
	defer C.free(unsafe.Pointer(pt))
	defer C.free(unsafe.Pointer(pf))
	ret, err := C._iconv_open(pt, pf)
	if err != nil {
		return nil, err
	}
	return &Iconv{ret}, nil
}

func (cd *Iconv) Close() error {
	_, err := C._iconv_close(cd.pointer)
	return err
}

func (cd *Iconv) Conv(input string) (result string, err error) {
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
		_, err := C._iconv(cd.pointer,
			C.uintptr(unsafe.Pointer(&inptr)), &inbytes,
			C.uintptr(unsafe.Pointer(&outptr)), &outbytes)
		buf.Write(outbuf[:len(outbuf)-int(outbytes)])
		if err != nil && err != E2BIG {
			return buf.String(), err
		}
	}

	return buf.String(), nil
}

func (cd *Iconv) ConvBytes(inbuf []byte) (result []byte, err error) {
	var buf bytes.Buffer

	if len(inbuf) == 0 {
		return []byte{}, nil
	}

	outbuf := make([]byte, len(inbuf)*3)
	inbytes := C.size_t(len(inbuf))
	inptr := &inbuf[0]

	for inbytes > 0 {
		outbytes := C.size_t(len(outbuf))
		outptr := &outbuf[0]
		_, err := C._iconv(cd.pointer,
			C.uintptr(unsafe.Pointer(&inptr)), &inbytes,
			C.uintptr(unsafe.Pointer(&outptr)), &outbytes)
		buf.Write(outbuf[:len(outbuf)-int(outbytes)])
		if err != nil && err != E2BIG {
			return buf.Bytes(), err
		}
	}

	return buf.Bytes(), nil
}
