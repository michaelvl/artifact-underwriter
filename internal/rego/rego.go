package rego

import (
	"context"
	"fmt"

	"github.com/michaelvl/artifact-underwriter/internal/policy/types"

	"github.com/open-policy-agent/opa/rego"
)

func Evaluate(policy *types.OciPolicy, input []map[string]any) (bool, error) {
	var rg *rego.Rego

	query := "data.governance.allow"
	if policy.Policy.Rego.Query != "" {
		query = policy.Policy.Rego.Query
	}
	switch {
	case policy.Policy.Rego.BundlePath != "":
		rg = rego.New(
			rego.Query("data.governance.allow"),
			rego.LoadBundle(policy.Policy.Rego.BundlePath),
			rego.Input(input),
		)
	case policy.Policy.Rego.Path != "":
		rg = rego.New(
			rego.Query(query),
			rego.Load([]string{policy.Policy.Rego.Path}, nil),
			rego.Input(input),
		)
	default:
		return false, fmt.Errorf("need either a policy or bundle path")
	}
	rs, err := rg.Eval(context.Background())
	if err != nil {
		return false, fmt.Errorf("evaluating rego: %w", err)
	}

	return rs.Allowed(), nil
}
