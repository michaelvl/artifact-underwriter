package oci

import (
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

func ResolveDigest(ociRef string) (name.Digest, error) {
	ref, err := name.ParseReference(ociRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("parsing oci ref: %w", err)
	}
	digest, err := ociremote.ResolveDigest(ref)
	if err != nil {
		return name.Digest{}, fmt.Errorf("resolving oci ref: %w", err)
	}
	return digest, nil
}
