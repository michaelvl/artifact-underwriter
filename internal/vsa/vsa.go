package vsa

import (
	"fmt"
	"encoding/json"

	vsa1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

func Generate(inputAttestations []oci.Signature, result string) error {
	var inputs []*vsa1.VerificationSummary_InputAttestation
	for idx := range inputAttestations {
		att := inputAttestations[idx]
		digest, err := att.Digest()
		if err != nil {
			return err
		}
		inputs = append(inputs, &vsa1.VerificationSummary_InputAttestation{
			Uri: "uriiii",
			Digest: map[string]string{digest.Algorithm: digest.Hex},
		})
	}

	predicate := &vsa1.VerificationSummary{
		InputAttestations:  inputs,
		VerificationResult: result,
	}

	jsonText, err := json.Marshal(predicate)
	if err != nil {
		return err
	}

	fmt.Printf("vsa: %v\n", string(jsonText))
	return nil
}
