package policy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"sigs.k8s.io/yaml"
)

type Attestation struct {
	Type       string `yaml:"type"`
	RegoPolicy string `yaml:"regoPolicy"`
}

type Certificate struct {
	IdentityRegexp string `yaml:"identityRegexp"`
	OidcIssuer     string `yaml:"oidcIssuer"`
}

type Functionary struct {
	Type        string      `yaml:"type"`
	Certificate Certificate `yaml:"certificate"`
}

type Step struct {
	Name          string        `yaml:"name"`
	Attestations  []Attestation `yaml:"attestations"`
	Functionaries []Functionary `yaml:"functionaries"`
}

type Policy struct {
	Kind    string       `yaml:"kind"`
	Steps   []Step       `yaml:"steps"`
}

func Load(fname string) (*Policy, error) {
	yamlFile, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	policy := &Policy{}
	err = yaml.Unmarshal(yamlFile, policy)
	if err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}
	return policy, nil
}

func (policy *Policy) Evaluate(ctx context.Context, ociRef, outputAttestationPath string) error {
	var err error
	var identities []cosign.Identity

	ref, err := name.ParseReference(ociRef)
	if err != nil {
		return fmt.Errorf("parsing ref: %w", err)
	}

	// FIXME, this is not correct. Use separate identities for different attestation types
	for _, step := range policy.Steps {
		for _, functionary := range step.Functionaries {
			ident := cosign.Identity{}
			if functionary.Type == "fulcio" {
				ident.SubjectRegExp = functionary.Certificate.IdentityRegexp
				ident.Issuer = functionary.Certificate.OidcIssuer
				identities = append(identities, ident)
			}
		}
	}

	co := cosign.CheckOpts{
		ClaimVerifier:     cosign.IntotoSubjectClaimVerifier,
		// RekorClient:       rekorClient,
		Identities:        identities,
	}
	co.RootCerts, err = fulcio.GetRoots()
	if err != nil {
		return fmt.Errorf("getting Fulcio roots: %w", err)
	}
	co.IntermediateCerts, err = fulcio.GetIntermediates()
	if err != nil {
		return fmt.Errorf("getting Fulcio intermediates: %w", err)
	}
	co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
	if err != nil {
		return fmt.Errorf("getting Rekor public keys: %w", err)
	}
	co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
	if err != nil {
		return fmt.Errorf("getting ct public keys: %w", err)
	}
	verified, bundleVerified, err := cosign.VerifyImageAttestations(ctx, ref, &co)
	if err != nil || !bundleVerified {
		return fmt.Errorf("verifying attestations: %w", err)
	}

	// fmt.Printf(">> %v: %v\n", len(verified), bundleVerified)

	var input []map[string]any

	for idx := range verified {
		attPayload, err := verified[idx].Payload()
		if err != nil {
			return fmt.Errorf("getting attestation payload: %w", err)
		}
		var attData map[string]any
		if err = json.Unmarshal(attPayload, &attData); err != nil {
			return fmt.Errorf("unmarshalling attestation data: %w", err)
		}
		attEncoded, ok := attData["payload"]
		if !ok {
			return fmt.Errorf("unexpected format: %w", err)
		}
		attDecoded, err := base64.StdEncoding.DecodeString(attEncoded.(string))
		if err != nil {
			return fmt.Errorf("decoding attestation: %w", err)
		}

		// fmt.Printf("> %+v\n", string(attDecoded))
		var attestation map[string]any
		if err := json.Unmarshal(attDecoded, &attestation); err != nil {
			return fmt.Errorf("decoding attestation json: %w", err)
		}

		input = append(input, attestation)
	}

	if outputAttestationPath != "" {
		f, err := os.Create(outputAttestationPath)
		if err != nil {
			return fmt.Errorf("opening attestation file: %w", err)
		}

		attText, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("marshalling attestation to json: %w", err)
		}
		w := bufio.NewWriter(f)
		_, err = w.WriteString(string(attText))
		if err != nil {
			return fmt.Errorf("writing attestation json to file: %w", err)
		}
	}

	return nil
}
