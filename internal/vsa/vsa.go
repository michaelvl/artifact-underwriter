package vsa

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	vsa1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	ita1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

// FIXME: Local copy since the vsa1 and specs
// https://slsa.dev/spec/v1.0/verification_summary differ in timestamp
// representation
type VerificationSummary struct {
	Verifier           *vsa1.VerificationSummary_Verifier           `json:"verifier"`
	TimeVerified       string                                       `json:"timeVerified"`
	InputAttestations  []*vsa1.VerificationSummary_InputAttestation `json:"inputAttestations"`
	VerificationResult string                                       `json:"verificationResult"`
	VerifiedLevels     []string                                     `json:"verifiedLevels"`
	SlsaVersion        string                                       `json:"slsaVersion"`
}

func Generate(subject name.Digest, inputAttestations []oci.Signature, result string, verificationLvls []string, verifierID string) (*in_toto.Statement, error) {
	var inputs []*vsa1.VerificationSummary_InputAttestation

	parts := strings.Split(subject.DigestStr(), ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("cannot detect digest algorithm or digest")
	}
	alg := parts[0]
	dig := parts[1]

	for idx := range inputAttestations {
		att := inputAttestations[idx]
		digest, err := att.Digest()
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, &vsa1.VerificationSummary_InputAttestation{
			Uri:    subject.Repository.Name(), // FIXME this url is not strictly correct
			Digest: map[string]string{digest.Algorithm: digest.Hex},
		})
	}

	predicate := &VerificationSummary{
		Verifier: &vsa1.VerificationSummary_Verifier{
			Id: verifierID,
		},
		InputAttestations:  inputs,
		TimeVerified:       time.Now().Format(time.RFC3339),
		VerificationResult: result,
		VerifiedLevels:     verificationLvls,
		SlsaVersion:        "1.0",
	}
	statement := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          ita1.StatementTypeUri,
			PredicateType: "https://slsa.dev/verification_summary/v1",
			Subject: []in_toto.Subject{
				in_toto.Subject{
					Name: subject.Repository.Name(),
					Digest: map[string]string{
						alg: dig,
					},
				},
			},
		},
		Predicate: predicate,
	}

	return &statement, nil
}
