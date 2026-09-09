package passport

import (
	"errors"
	"fmt"
	"slices"

	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

// ManifestFieldCount is the number of manifest fields bound by a passport.
const ManifestFieldCount = zkp.ManifestFieldCount

// AllowlistDepth is the Merkle depth of a manifest allowlist; a policy may
// list up to 2^AllowlistDepth allowed (field, value) pairs.
const AllowlistDepth = zkp.AllowlistDepth

// ManifestFieldNames names the manifest fields in circuit order.
var ManifestFieldNames = [ManifestFieldCount]string{"modelId", "systemPromptHash", "toolPolicyHash", "permissionScope"}

// Manifest version policy errors.
var (
	ErrManifestFieldImmutable  = errors.New("manifest field changed but the policy does not permit changing it")
	ErrManifestValueNotAllowed = errors.New("manifest field changed to a value outside the policy allowlist")
	ErrAllowlistTooLarge       = errors.New("manifest allowlist exceeds the tree capacity")
)

// ManifestFields maps a manifest into field elements in circuit order.
func ManifestFields(m Manifest) [ManifestFieldCount]field.Element {
	values := manifestValues(m)
	var out [ManifestFieldCount]field.Element
	for i, v := range values {
		out[i] = field.FromText(v)
	}
	return out
}

func manifestValues(m Manifest) [ManifestFieldCount]string {
	return [ManifestFieldCount]string{m.ModelID, m.SystemPromptHash, m.ToolPolicyHash, m.PermissionScope}
}

// ManifestVersionPolicy says which manifest fields may differ between the
// manifest a certificate was issued for and the agent's current manifest,
// and which new values are acceptable. A field with no allowed values is
// immutable; an empty policy permits no change at all.
type ManifestVersionPolicy struct {
	// Allowed maps a field index (see ManifestFieldNames) to the values the
	// field may take after a change.
	Allowed map[int][]string
}

// StrictManifestPolicy permits no manifest change.
func StrictManifestPolicy() ManifestVersionPolicy {
	return ManifestVersionPolicy{}
}

// Mutable reports whether field i may change.
func (p ManifestVersionPolicy) Mutable(i int) bool {
	return len(p.Allowed[i]) > 0
}

// Mask packs the mutable flags into an integer: bit i is field i.
func (p ManifestVersionPolicy) Mask() int64 {
	var mask int64
	for i := 0; i < ManifestFieldCount; i++ {
		if p.Mutable(i) {
			mask |= 1 << i
		}
	}
	return mask
}

// Permits reports whether moving from the certified manifest to the current
// one is allowed. It mirrors the circuit's check so that the prover can fail
// early with a clear reason.
func (p ManifestVersionPolicy) Permits(certified, current Manifest) error {
	c, n := manifestValues(certified), manifestValues(current)
	for i := range c {
		if c[i] == n[i] {
			continue
		}
		if !p.Mutable(i) {
			return fmt.Errorf("%w: %s", ErrManifestFieldImmutable, ManifestFieldNames[i])
		}
		if !slices.Contains(p.Allowed[i], n[i]) {
			return fmt.Errorf("%w: %s=%q", ErrManifestValueNotAllowed, ManifestFieldNames[i], n[i])
		}
	}
	return nil
}

// AllowlistLeaf is the Merkle leaf for one allowed value of a field. The
// field index is offset by one so that padding leaves (zero) cannot collide
// with a real entry.
func AllowlistLeaf(fieldIndex int, value string) (field.Element, error) {
	return field.Hash(field.FromInt(int64(fieldIndex+1)), field.FromText(value))
}

// ManifestAllowlist is the Merkle tree over a policy's allowed (field, value)
// pairs. The service publishes it; only its root enters the policy hash.
type ManifestAllowlist struct {
	Root   field.Element
	levels [][]field.Element // levels[0] are the padded leaves, levels[AllowlistDepth] is [root]
	index  map[field.Element]int
}

// MerklePath is an inclusion path for one leaf. Bit k of Index says whether
// the node at level k is the right child.
type MerklePath struct {
	Index    int64
	Siblings [AllowlistDepth]field.Element
}

// EmptyPath is the placeholder path used for fields that did not change.
func EmptyPath() MerklePath {
	var p MerklePath
	for i := range p.Siblings {
		p.Siblings[i] = "0"
	}
	return p
}

// BuildManifestAllowlist builds the Merkle tree for a policy.
func BuildManifestAllowlist(p ManifestVersionPolicy) (*ManifestAllowlist, error) {
	size := 1 << AllowlistDepth
	var leaves []field.Element
	index := map[field.Element]int{}
	for i := 0; i < ManifestFieldCount; i++ {
		for _, v := range p.Allowed[i] {
			leaf, err := AllowlistLeaf(i, v)
			if err != nil {
				return nil, err
			}
			if _, dup := index[leaf]; dup {
				continue
			}
			index[leaf] = len(leaves)
			leaves = append(leaves, leaf)
		}
	}
	if len(leaves) > size {
		return nil, fmt.Errorf("%w: %d entries, capacity %d", ErrAllowlistTooLarge, len(leaves), size)
	}
	for len(leaves) < size {
		leaves = append(leaves, "0")
	}
	levels := [][]field.Element{leaves}
	for d := 0; d < AllowlistDepth; d++ {
		prev := levels[d]
		next := make([]field.Element, len(prev)/2)
		for j := range next {
			h, err := field.Hash(prev[2*j], prev[2*j+1])
			if err != nil {
				return nil, err
			}
			next[j] = h
		}
		levels = append(levels, next)
	}
	return &ManifestAllowlist{Root: levels[AllowlistDepth][0], levels: levels, index: index}, nil
}

// Path returns the inclusion path of a (field, value) pair.
func (a *ManifestAllowlist) Path(fieldIndex int, value string) (MerklePath, bool) {
	leaf, err := AllowlistLeaf(fieldIndex, value)
	if err != nil {
		return MerklePath{}, false
	}
	pos, ok := a.index[leaf]
	if !ok {
		return MerklePath{}, false
	}
	p := MerklePath{Index: int64(pos)}
	for d := 0; d < AllowlistDepth; d++ {
		p.Siblings[d] = a.levels[d][pos^1]
		pos >>= 1
	}
	return p, true
}
