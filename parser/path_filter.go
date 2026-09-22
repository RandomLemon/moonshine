package parser

import (
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/shankarapailoor/moonshine/strace_types"
)

// syzkaller treats a program that names an absolute path as a sandbox escape
// and rejects the whole program (prog/validation.go: "escaping filename",
// prog/rand.go: escapingFilename -- anything filepath.Clean()s to a leading '/'
// or a leading ".."). A CUDA process opens dozens of such paths while starting
// up (ld.so, libcuda.so.1, /proc entries, /dev/shm, unix sockets under /tmp),
// so keeping any of them would make every converted program unusable -- and in
// -distill mode the same validation runs on the diluted programs, where the
// rejection is a panic rather than a skipped seed.
//
// Device nodes are the exception: the open/openat hooks rewrite those calls to
// syz_open_dev$*, whose path lives in the syscall description as a string
// constant and is never validated as a filename of the program.

// pathArgIndex returns the index of the argument syzkaller validates as a
// filename for the calls that take one, or -1 for every other call.
func pathArgIndex(callName string) int {
	switch callName {
	case "open", "stat", "stat64", "lstat", "access", "unlink", "readlink",
		"mkdir", "rmdir", "chdir", "chmod", "chown", "truncate", "execve":
		return 0
	case "symlink":
		return 1 // oldpath is arg0, newpath (the validated one) is arg1
	case "openat", "newfstatat", "faccessat", "unlinkat", "mkdirat", "readlinkat",
		"fchmodat", "fchownat", "utimensat":
		return 1
	}
	return -1
}

// isAbsolutePath returns whether a traced string names a file absolutely.
func isAbsolutePath(buf string) bool {
	// BufferType values keep their trailing NUL, and a directory-relative
	// "../../nvidiactl" is rejected by syzkaller just like "/lib/libc.so.6".
	return strings.HasPrefix(buf, "/") || strings.HasPrefix(buf, "..")
}

// isAbsolutePathCall reports whether the call names a file by an absolute path
// in the argument syzkaller validates.
func isAbsolutePathCall(syscall *strace_types.Syscall) bool {
	idx := pathArgIndex(syscall.CallName)
	if idx < 0 || idx >= len(syscall.Args) {
		return false
	}
	buf, ok := syscall.Args[idx].(*strace_types.BufferType)
	return ok && isAbsolutePath(buf.Val)
}

// isUnixAbsSocket reports whether the call connects or binds a unix socket to
// an absolute path. The path is nested in a sockaddr, so the whole argument is
// searched.
func isUnixAbsSocket(syscall *strace_types.Syscall) bool {
	switch syscall.CallName {
	case "connect", "bind":
	default:
		return false
	}
	if len(syscall.Args) < 2 {
		return false
	}
	return hasAbsoluteBuffer(syscall.Args[1])
}

// hasAbsoluteBuffer reports whether any nested buffer of the IR node holds an
// absolute path.
func hasAbsoluteBuffer(node strace_types.Type) bool {
	switch a := node.(type) {
	case *strace_types.BufferType:
		return isAbsolutePath(a.Val)
	case *strace_types.PointerType:
		return a.Res != nil && hasAbsoluteBuffer(a.Res)
	case *strace_types.StructType:
		for _, field := range a.Fields {
			if hasAbsoluteBuffer(field) {
				return true
			}
		}
	case *strace_types.ArrayType:
		for _, elem := range a.Elems {
			if hasAbsoluteBuffer(elem) {
				return true
			}
		}
	case *strace_types.Field:
		return hasAbsoluteBuffer(a.Val)
	}
	return false
}

// isKnownDevice reports whether the path opened by an open/openat call matches
// a syz_open_dev pattern, i.e. whether the call is rebound to a
// device-specific resource and its path stops being a program filename.
func isKnownDevice(syscall *strace_types.Syscall) bool {
	var idx int
	switch syscall.CallName {
	case "open":
		idx = 0
	case "openat":
		idx = 1
	default:
		return false
	}
	if idx >= len(syscall.Args) {
		return false
	}
	buf, ok := syscall.Args[idx].(*strace_types.BufferType)
	if !ok {
		return false
	}
	_, _, ok = openDevVariant(strings.TrimRight(buf.Val, "\x00"))
	return ok
}

// skipAbsolutePath reports whether the call must be dropped because it names an
// absolute path. Returns false while a device node is being opened: those are
// rebound to syz_open_dev$* and are the calls worth fuzzing.
func skipAbsolutePath(syscall *strace_types.Syscall) bool {
	if isAbsolutePathCall(syscall) && !isKnownDevice(syscall) {
		log.Logf(3, "Skipping absolute-path call: %s", syscall.CallName)
		return true
	}
	if isUnixAbsSocket(syscall) {
		log.Logf(3, "Skipping absolute-path unix socket: %s", syscall.CallName)
		return true
	}
	return false
}
