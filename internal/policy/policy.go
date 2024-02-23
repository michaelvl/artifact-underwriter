package policy

import (
	"fmt"
	"os"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/michaelvl/artifact-underwriter/internal/attestations"
	"github.com/michaelvl/artifact-underwriter/internal/policy/types"
	"github.com/michaelvl/artifact-underwriter/internal/rego"
	"sigs.k8s.io/yaml"
)

func Load(fname string) (*types.OciPolicy, error) {
	yamlFile, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	policy := &types.OciPolicy{}
	err = yaml.Unmarshal(yamlFile, policy)
	if err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}
	return policy, nil
}

func Evaluate(policy *types.OciPolicy, statements []in_toto.Statement) (bool, error) {
	jsonData, err := attestations.StatementsToJson(statements)
	if err != nil {
		return false, fmt.Errorf("decoding attestions json: %w", err)
	}

	allowed, err := rego.Evaluate(policy, jsonData)
	if err != nil {
		return false, fmt.Errorf("evaluating rego policy: %w", err)
	}
	return allowed, nil
}
