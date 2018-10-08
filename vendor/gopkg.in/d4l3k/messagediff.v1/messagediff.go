package messagediff

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
	"unsafe"
)

// PrettyDiff does a deep comparison and returns the nicely formated results.
// See DeepDiff for more details.
func PrettyDiff(a, b interface{}, options ...Option) (string, bool) {
	d, equal := DeepDiff(a, b, options...)
	var dstr []string
	for path, added := range d.Added {
		dstr = append(dstr, fmt.Sprintf("added: %s = %#v\n", path.String(), added))
	}
	for path, removed := range d.Removed {
		dstr = append(dstr, fmt.Sprintf("removed: %s = %#v\n", path.String(), removed))
	}
	for path, modified := range d.Modified {
		dstr = append(dstr, fmt.Sprintf("modified: %s = %#v\n", path.String(), modified))
	}
	sort.Strings(dstr)
	return strings.Join(dstr, ""), equal
}

// DeepDiff does a deep comparison and returns the results.
// If the field is time.Time, use Equal to compare
func DeepDiff(a, b interface{}, options ...Option) (*Diff, bool) {
	d := newDiff()
	opts := &opts{}
	for _, o := range options {
		o.apply(opts)
	}
	return d, d.diff(reflect.ValueOf(a), reflect.ValueOf(b), nil, opts)
}

func newDiff() *Diff {
	return &Diff{
		Added:    make(map[*Path]interface{}),
		Removed:  make(map[*Path]interface{}),
		Modified: make(map[*Path]interface{}),
		visited:  make(map[visit]bool),
	}
}

func (d *Diff) diff(aVal, bVal reflect.Value, path Path, opts *opts) bool {
	// The array underlying `path` could be modified in subsequent
	// calls. Make sure we have a local copy.
	localPath := make(Path, len(path))
	copy(localPath, path)

	// Validity checks. Should only trigger if nil is one of the original arguments.
	if !aVal.IsValid() && !bVal.IsValid() {
		return true
	}
	if !bVal.IsValid() {
		d.Modified[&localPath] = nil
		return false
	} else if !aVal.IsValid() {
		d.Modified[&localPath] = bVal.Interface()
		return false
	}

	if aVal.Type() != bVal.Type() {
		d.Modified[&localPath] = bVal.Interface()
		return false
	}
	kind := aVal.Kind()

	// Borrowed from the reflect package to handle recursive data structures.
	hard := func(k reflect.Kind) bool {
		switch k {
		case reflect.Array, reflect.Map, reflect.Slice, reflect.Struct:
			return true
		}
		return false
	}

	if aVal.CanAddr() && bVal.CanAddr() && hard(kind) {
		addr1 := unsafe.Pointer(aVal.UnsafeAddr())
		addr2 := unsafe.Pointer(bVal.UnsafeAddr())
		if uintptr(addr1) > uintptr(addr2) {
			// Canonicalize order to reduce number of entries in visited.
			// Assumes non-moving garbage collector.
			addr1, addr2 = addr2, addr1
		}

		// Short circuit if references are already seen.
		typ := aVal.Type()
		v := visit{addr1, addr2, typ}
		if d.visited[v] {
			return true
		}

		// Remember for later.
		d.visited[v] = true
	}
	// End of borrowed code.

	equal := true
	switch kind {
	case reflect.Map, reflect.Ptr, reflect.Func, reflect.Chan, reflect.Slice:
		if aVal.IsNil() && bVal.IsNil() {
			return true
		}
		if aVal.IsNil() || bVal.IsNil() {
			d.Modified[&localPath] = bVal.Interface()
			return false
		}
	}

	switch kind {
	case reflect.Array, reflect.Slice:
		aLen := aVal.Len()
		bLen := bVal.Len()
		for i := 0; i < min(aLen, bLen); i++ {
			localPath := append(localPath, SliceIndex(i))
			if eq := d.diff(aVal.Index(i), bVal.Index(i), localPath, opts); !eq {
				equal = false
			}
		}
		if aLen > bLen {
			for i := bLen; i < aLen; i++ {
				localPath := append(localPath, SliceIndex(i))
				d.Removed[&localPath] = aVal.Index(i).Interface()
				equal = false
			}
		} else if aLen < bLen {
			for i := aLen; i < bLen; i++ {
				localPath := append(localPath, SliceIndex(i))
				d.Added[&localPath] = bVal.Index(i).Interface()
				equal = false
			}
		}
	case reflect.Map:
		for _, key := range aVal.MapKeys() {
			aI := aVal.MapIndex(key)
			bI := bVal.MapIndex(key)
			localPath := append(localPath, MapKey{key.Interface()})
			if !bI.IsValid() {
				d.Removed[&localPath] = aI.Interface()
				equal = false
			} else if eq := d.diff(aI, bI, localPath, opts); !eq {
				equal = false
			}
		}
		for _, key := range bVal.MapKeys() {
			aI := aVal.MapIndex(key)
			if !aI.IsValid() {
				bI := bVal.MapIndex(key)
				localPath := append(localPath, MapKey{key.Interface()})
				d.Added[&localPath] = bI.Interface()
				equal = false
			}
		}
	case reflect.Struct:
		typ := aVal.Type()
		// If the field is time.Time, use Equal to compare
		if typ.String() == "time.Time" {
			aTime := aVal.Interface().(time.Time)
			bTime := bVal.Interface().(time.Time)
			if !aTime.Equal(bTime) {
				d.Modified[&localPath] = bVal.Interface().(time.Time).String()
				equal = false
			}
		} else {
			for i := 0; i < typ.NumField(); i++ {
				index := []int{i}
				field := typ.FieldByIndex(index)
				if field.Tag.Get("testdiff") == "ignore" { // skip fields marked to be ignored
					continue
				}
				if _, skip := opts.ignoreField[field.Name]; skip {
					continue
				}
				localPath := append(localPath, StructField(field.Name))
				aI := unsafeReflectValue(aVal.FieldByIndex(index))
				bI := unsafeReflectValue(bVal.FieldByIndex(index))
				if eq := d.diff(aI, bI, localPath, opts); !eq {
					equal = false
				}
			}
		}
	case reflect.Ptr:
		equal = d.diff(aVal.Elem(), bVal.Elem(), localPath, opts)
	default:
		if reflect.DeepEqual(aVal.Interface(), bVal.Interface()) {
			equal = true
		} else {
			d.Modified[&localPath] = bVal.Interface()
			equal = false
		}
	}
	return equal
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// During deepValueEqual, must keep track of checks that are
// in progress.  The comparison algorithm assumes that all
// checks in progress are true when it reencounters them.
// Visited comparisons are stored in a map indexed by visit.
// This is borrowed from the reflect package.
type visit struct {
	a1  unsafe.Pointer
	a2  unsafe.Pointer
	typ reflect.Type
}

// Diff represents a change in a struct.
type Diff struct {
	Added, Removed, Modified map[*Path]interface{}
	visited                  map[visit]bool
}

// Path represents a path to a changed datum.
type Path []PathNode

func (p Path) String() string {
	var out string
	for _, n := range p {
		out += n.String()
	}
	return out
}

// PathNode represents one step in the path.
type PathNode interface {
	String() string
}

// StructField is a path element representing a field of a struct.
type StructField string

func (n StructField) String() string {
	return fmt.Sprintf(".%s", string(n))
}

// MapKey is a path element representing a key of a map.
type MapKey struct {
	Key interface{}
}

func (n MapKey) String() string {
	return fmt.Sprintf("[%#v]", n.Key)
}

// SliceIndex is a path element representing a index of a slice.
type SliceIndex int

func (n SliceIndex) String() string {
	return fmt.Sprintf("[%d]", n)
}

type opts struct {
	ignoreField map[string]struct{}
}

// Option is an option to specify in diff
type Option interface {
	apply(*opts)
}

// IgnoreStructField return an option of IgnoreFieldOption
func IgnoreStructField(field string) Option {
	return IgnoreFieldOption{
		Field: field,
	}
}

// IgnoreFieldOption is an option for specifying a field that does not diff
type IgnoreFieldOption struct {
	Field string
}

func (i IgnoreFieldOption) apply(opts *opts) {
	if opts.ignoreField == nil {
		opts.ignoreField = map[string]struct{}{}
	}
	opts.ignoreField[i.Field] = struct{}{}
}
