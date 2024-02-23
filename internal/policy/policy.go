package policy

import (
	"fmt"
	"log"
	"os"

	"github.com/michaelvl/artifact-underwriter/internal/attestations"
	"github.com/michaelvl/artifact-underwriter/internal/policy/types"
	"sigs.k8s.io/yaml"
	"github.com/in-toto/in-toto-golang/in_toto"
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

func Evaluate(policy *types.OciPolicy, statements []in_toto.Statement) error {
	jsonData, err := attestations.StatementsToJson(statements)
	if err != nil {
		return fmt.Errorf("decoding attestions json: %w", err)
	}

	// TODO

	log.Printf("Len evaluate json: %v\n", len(jsonData))

	return nil
}
