package types

type OciPolicy struct {
	Kind   string `json:"kind"`
	Steps  []Step `json:"steps"`
	Policy Policy `json:"policy"`
}

type Step struct {
	Name          string        `json:"name"`
	Attestations  []Attestation `json:"attestations"`
	Functionaries []Functionary `json:"functionaries"`
}

type Attestation struct {
	// In-toto predicate type, see https://github.com/in-toto/attestation/tree/main/spec/predicates
	Type string `json:"type"`
}

// Functionary defines who are allowed to sign a given attestation
type Functionary struct {
	// Type of the functionary. Currently only 'sigstore-keyless' is supported
	Type        string      `json:"type"`
	Certificate Certificate `json:"certificate"`
}

// Certificate define the identity of a functionary
type Certificate struct {
	// OIDC subject regular expression
	IdentityRegexp string `json:"identityRegexp"`
	// OIDC issuer URL
	OidcIssuer string `json:"oidcIssuer"`
}

type Policy struct {
	Rego RegoPolicy `json:"rego"`
}

type RegoPolicy struct {
	// The query defining policy valuation result. A boolean result is expected, with 'true' indicating validation success
	Query string `json:"query"`
	// OpenPolicyAgent policy bundle path. See https://www.openpolicyagent.org/docs/latest/management-bundles
	BundlePath string `json:"bundle"`
	// Path to Rego policy files. May be either a file or a directory
	Path string `json:"path"`
	// Not yet supported
	// URI        string `json:"uri"`
}
