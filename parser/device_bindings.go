package parser

import (
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/shankarapailoor/moonshine/strace_types"
)

// openDevPattern is the device path template of a syz_open_dev$* variant. '#'
// stands for a decimal device index (e.g. /dev/nvidia#) and is captured when
// the template is matched against a traced path.
type openDevPattern struct {
	pattern string
	suffix  string
}

// matchPath reports whether path matches the template and returns the device
// index captured by the first '#' wildcard (-1 when the template has none).
func (o openDevPattern) matchPath(path string) (bool, int) {
	if len(o.pattern) != len(path) {
		return false, -1
	}
	id := -1
	for i := 0; i < len(o.pattern); i++ {
		if o.pattern[i] == path[i] {
			continue
		}
		if o.pattern[i] != '#' || path[i] < '0' || path[i] > '9' {
			return false, -1
		}
		if id == -1 {
			id = 0
		}
		id = id*10 + int(path[i]-'0')
	}
	return true, id
}

// openDevPatterns holds the path template of every syz_open_dev$* variant;
// dupVariantSuffixes maps a resource type name to the dup variant suffix that
// preserves it (fd_nvidiactl -> nvidiactl). Both are built once, before any
// trace is parsed, by BuildDeviceBindings.
var (
	openDevPatterns    []openDevPattern
	dupVariantSuffixes map[string]string
)

// BuildDeviceBindings records the device identity of descriptors. That identity
// is the first component of every variant key here: ioctl variants are selected
// by (fd resource, command value) and dup variants by the resource of the
// descriptor being duplicated. Without these tables every descriptor stays a
// plain fd, so no device-specific variant can be selected.
func BuildDeviceBindings(target *prog.Target) {
	openDevPatterns = buildOpenDevPatterns(target)
	dupVariantSuffixes = buildDupVariantSuffixes(target)
	log.Logf(2, "Device bindings: %d open patterns, %d dup variants",
		len(openDevPatterns), len(dupVariantSuffixes))
}

// buildOpenDevPatterns collects the path template and suffix of every
// syz_open_dev$* variant. Automatic (machine generated) variants are skipped:
// they are not reachable from a trace, mirroring trace2syz's variant map.
func buildOpenDevPatterns(target *prog.Target) []openDevPattern {
	var patterns []openDevPattern
	for _, call := range target.Syscalls {
		if call.Attrs.Automatic || call.CallName != "syz_open_dev" || !strings.Contains(call.Name, "$") {
			continue
		}
		dev, ok := call.Args[0].Type.(*prog.PtrType)
		if !ok {
			continue
		}
		buf, ok := dev.Elem.(*prog.BufferType)
		if !ok || buf.Kind != prog.BufferString {
			continue
		}
		suffix := strings.Split(call.Name, "$")[1]
		for _, val := range buf.Values {
			patterns = append(patterns, openDevPattern{
				pattern: strings.TrimRight(val, "\x00"),
				suffix:  suffix,
			})
		}
	}
	return patterns
}

// buildDupVariantSuffixes maps the resource a dup/dup2/dup3 variant returns to
// that variant's suffix, e.g. fd_nvidiactl -> nvidiactl. Duplicates keep the
// first variant seen, so the choice does not depend on target.Syscalls order.
func buildDupVariantSuffixes(target *prog.Target) map[string]string {
	m := make(map[string]string)
	for _, call := range target.Syscalls {
		switch call.CallName {
		case "dup", "dup2", "dup3":
		default:
			continue
		}
		if call.Attrs.Automatic || !strings.Contains(call.Name, "$") {
			continue
		}
		ret, ok := call.Ret.(*prog.ResourceType)
		if !ok {
			continue
		}
		if _, exists := m[ret.TypeName]; !exists {
			m[ret.TypeName] = strings.Split(call.Name, "$")[1]
		}
	}
	return m
}

// openDevVariant returns the suffix of the syz_open_dev$* variant whose path
// template matches path, plus the device index captured by its '#' wildcard.
// The path must already be stripped of its trailing NUL bytes.
func openDevVariant(path string) (string, int, bool) {
	for _, pat := range openDevPatterns {
		if matched, id := pat.matchPath(path); matched {
			return pat.suffix, id, true
		}
	}
	return "", 0, false
}

// selectOpenDev rebinds an open()/openat() call to the syz_open_dev$<dev>
// variant whose path template matches the traced path; pathIdx is the index of
// the path argument. The call is rewritten to syz_open_dev's (dev, id, flags)
// argument layout: the traced path stays in place, the captured device index is
// inserted after it and a leading openat dirfd is dropped. A descriptor opened
// this way carries the device resource type, which is what lets later ioctls
// and dups on it be matched against the device's own variants.
func selectOpenDev(ctx *Context, pathIdx int) bool {
	args := ctx.CurrentStraceCall.Args
	if pathIdx >= len(args) {
		return false
	}
	buf, ok := args[pathIdx].(*strace_types.BufferType)
	if !ok {
		return false
	}
	suffix, id, ok := openDevVariant(strings.TrimRight(buf.Val, "\x00"))
	if !ok {
		return false
	}
	meta, ok := ctx.Target.SyscallMap["syz_open_dev$"+suffix]
	if !ok {
		return false
	}
	if id < 0 {
		id = 0
	}
	ctx.CurrentSyzCall.Meta = meta
	bound := make([]strace_types.Type, 0, len(args)+1)
	bound = append(bound, args[pathIdx],
		strace_types.NewExpression(strace_types.NewIntType(int64(id))))
	ctx.CurrentStraceCall.Args = append(bound, args[pathIdx+1:]...)
	return true
}

// dupVariantSuffix returns the dup/dup2/dup3 variant suffix that preserves the
// resource type of the descriptor being duplicated.
//
// The cache is keyed by the root resource kind (fd), so the cached argument
// still carries the device-specific type the descriptor was opened as; unlike
// trace2syz there is no second, per-device key to consult.
func dupVariantSuffix(ctx *Context) (string, bool) {
	args := ctx.CurrentStraceCall.Args
	meta := ctx.CurrentSyzCall.Meta
	if len(args) == 0 || meta == nil || len(meta.Args) == 0 {
		return "", false
	}
	arg := ctx.Cache.Get(meta.Args[0].Type, args[0])
	if arg == nil {
		return "", false
	}
	res, ok := arg.Type().(*prog.ResourceType)
	if !ok {
		return "", false
	}
	suffix, ok := dupVariantSuffixes[res.TypeName]
	return suffix, ok
}
