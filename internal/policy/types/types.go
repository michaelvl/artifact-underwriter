package types

type Attestation struct {
	Type string `json:"type"`
}

type Certificate struct {
	IdentityRegexp string `json:"identityRegexp"`
	OidcIssuer     string `json:"oidcIssuer"`
}

type Functionary struct {
	Type        string      `json:"type"`
	Certificate Certificate `json:"certificate"`
}

type Policy struct {
	Rego RegoPolicy `json:"rego"`
}

type RegoPolicy struct {
	Bundle string `json:"bundle"`
	Path   string `json:"path"`
	URI    string `json:"uri"`
}

type Step struct {
	Name          string        `json:"name"`
	Attestations  []Attestation `json:"attestations"`
	Functionaries []Functionary `json:"functionaries"`
}

type OciPolicy struct {
	Kind   string `json:"kind"`
	Steps  []Step `json:"steps"`
	Policy Policy `json:"policy"`
}
