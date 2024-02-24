package vsa

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	vsa1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	ita1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

func Generate(subject name.Digest, inputAttestations []oci.Signature, result, verificationLvl,verifierId string) (*in_toto.Statement, error) {
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

	predicate := &vsa1.VerificationSummary{
		Verifier: &vsa1.VerificationSummary_Verifier{
			Id: verifierId,
		},
		InputAttestations:  inputs,
		VerificationResult: result,
		VerifiedLevels: verificationLvl,
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
