package rego

import (
	"context"
	"fmt"
	"os"

	"github.com/michaelvl/artifact-underwriter/internal/policy/types"

	"github.com/open-policy-agent/opa/rego"
)

func Evaluate(policy *types.OciPolicy, input []map[string]any) (bool, error) {
	policyData, err := os.ReadFile(policy.Policy.Rego.Path)
	if err != nil {
		return false, fmt.Errorf("reading file: %w", err)
	}

	rg := rego.New(
		rego.Query("data.governance.allow"),
		rego.Module(policy.Policy.Rego.Path, string(policyData)),
		rego.Input(input),
	)
	rs, err := rg.Eval(context.Background())
	if err != nil {
		return false, fmt.Errorf("evaluating rego: %w", err)
	}

	return rs.Allowed(), nil
}
