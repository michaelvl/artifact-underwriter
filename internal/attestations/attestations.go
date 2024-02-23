package attestations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/michaelvl/artifact-underwriter/internal/policy/types"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

func GetAttestations(ctx context.Context, digest name.Digest, policy *types.OciPolicy) ([]oci.Signature, []in_toto.Statement, error) {
	var err error
	var attestations []oci.Signature
	var statements []in_toto.Statement

	log.Printf("retreiving attestations for %v\n", digest)

	co := cosign.CheckOpts{
		ClaimVerifier: cosign.IntotoSubjectClaimVerifier,
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
		log.Printf("processing step %v\n", step.Name)
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

		verified, bundleVerified, err := cosign.VerifyImageAttestations(ctx, digest, &co)
		if err != nil || !bundleVerified {
			return nil, nil, fmt.Errorf("verifying attestations: %w", err)
		}
		log.Printf("found %v attestations\n", len(verified))

		for idx := range verified {
			att := verified[idx]
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
					attestations = append(attestations, att)
					statements = append(statements, statement)
				}
			}
		}
		log.Printf("matched %v attestions\n", len(attestations))
	}

	log.Printf("%v attestions:\n", len(attestations))
	for _, statement := range statements {
		log.Printf("type: %v\n", statement.PredicateType)
	}

	return attestations, statements, nil
}

func WriteStatements(statements []in_toto.Statement, outputPath string) error {
	jsonData, err := StatementsToJson(statements)
	if err != nil {
		return fmt.Errorf("decoding statement json: %w", err)
	}
	return WriteJson(jsonData, outputPath)
}

func WriteStatement(statement *in_toto.Statement, outputPath string) error {
	jsonData, err := StatementsToJson([]in_toto.Statement{*statement})
	if err != nil {
		return fmt.Errorf("decoding statement json: %w", err)
	}
	return WriteJson(&jsonData[0], outputPath)
}

func WriteJson(jsonData any, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("opening attestation file: %w", err)
	}
	defer f.Close()
	jsonText, err := json.Marshal(jsonData)
	if err != nil {
		return fmt.Errorf("marshalling attestation to json: %w", err)
	}
	st := string(jsonText)
	lenW, err := f.WriteString(st)
	if err != nil {
		return fmt.Errorf("writing attestation json to file: %w", err)
	}
	if lenW != len(st) {
		return fmt.Errorf("writing data to file")
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
