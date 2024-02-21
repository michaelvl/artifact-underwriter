package attestations

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/michaelvl/artifact-underwriter/internal/policy/types"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/in-toto/in-toto-golang/in_toto"
)

func GetAttestations(ctx context.Context, ociRef string, policy *types.OciPolicy) ([]oci.Signature, []in_toto.Statement, error) {
	var err error
	var attestations []oci.Signature
	var statements []in_toto.Statement

	ref, err := name.ParseReference(ociRef)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing ref: %w", err)
	}

	co := cosign.CheckOpts{
		ClaimVerifier:     cosign.IntotoSubjectClaimVerifier,
		// RekorClient:       rekorClient,
	}
	co.RootCerts, err = fulcio.GetRoots()
	if err != nil {
		return nil, nil, fmt.Errorf("getting Fulcio roots: %w", err)
	}
	co.IntermediateCerts, err = fulcio.GetIntermediates()
	if err != nil {
		return nil, nil, fmt.Errorf("getting Fulcio intermediates: %w", err)
	}
	co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting Rekor public keys: %w", err)
	}
	co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting ct public keys: %w", err)
	}

	for _, step := range policy.Steps {
		fmt.Printf(">> Step %v\n", step.Name)
		var identities []cosign.Identity
		for _, functionary := range step.Functionaries {
			ident := cosign.Identity{}
			if functionary.Type == "fulcio" {
				ident.SubjectRegExp = functionary.Certificate.IdentityRegexp
				ident.Issuer = functionary.Certificate.OidcIssuer
				identities = append(identities, ident)
			}
		}
		co.Identities = identities

		verified, bundleVerified, err := cosign.VerifyImageAttestations(ctx, ref, &co)
		if err != nil || !bundleVerified {
			return nil, nil, fmt.Errorf("verifying attestations: %w", err)
		}
		fmt.Printf(">> verified len %v\n", len(verified))

		for idx := range verified {
			att := verified[idx]
			attestations = append(attestations, att)
			attPayload, err := att.Payload()
			if err != nil {
				return nil, nil, fmt.Errorf("getting attestation payload: %w", err)
			}
			var attData map[string]any
			if err = json.Unmarshal(attPayload, &attData); err != nil {
				return nil, nil, fmt.Errorf("unmarshalling attestation data: %w", err)
			}
			attEncoded, ok := attData["payload"]
			if !ok {
				return nil, nil, fmt.Errorf("could not find payload in attestation: %w", err)
			}
			attDecoded, err := base64.StdEncoding.DecodeString(attEncoded.(string))
			if err != nil {
				return nil, nil, fmt.Errorf("decoding attestation: %w", err)
			}
			var statement in_toto.Statement
			if err := json.Unmarshal(attDecoded, &statement); err != nil {
				return nil, nil, fmt.Errorf("unmarshal in-toto statement: %w", err)
			}
			for _, attestation := range step.Attestations {
				if statement.PredicateType == attestation.Type {
					statements = append(statements, statement)
				}
			}
		}
		fmt.Printf(">> statements len %v\n", len(statements))
	}

	for _, statement := range statements {
		fmt.Printf(">> type: %v\n", statement.PredicateType)
	}

	return attestations, statements, nil
}

func WriteAttestations(statements []in_toto.Statement, outputPath string) error {
	jsonData, err := StatementsToJson(statements)
	if err != nil {
		return fmt.Errorf("decoding attestions json: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("opening attestation file: %w", err)
	}

	jsonText, err := json.Marshal(jsonData)
	if err != nil {
		return fmt.Errorf("marshalling attestation to json: %w", err)
	}
	w := bufio.NewWriter(f)
	_, err = w.WriteString(string(jsonText))
	if err != nil {
		return fmt.Errorf("writing attestation json to file: %w", err)
	}
	return nil
}

func StatementsToJson(statements []in_toto.Statement) ([]map[string]any, error) {
	var attestations []map[string]any

	for idx := range statements {
		var attestation map[string]any
		s := &statements[idx]
		payload, err := json.Marshal(s)
		if err != nil {
			return nil, fmt.Errorf("marshal statement: %w", err)
		}
		if err := json.Unmarshal(payload, &attestation); err != nil {
			return nil, fmt.Errorf("unmarshalling statement: %w", err)
		}
		attestations = append(attestations, attestation)
	}
	return attestations, nil
}
