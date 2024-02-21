package cmd

import (
	"context"
	"fmt"

	"github.com/michaelvl/artifact-underwriter/cmd/options"
	"github.com/michaelvl/artifact-underwriter/internal/attestations"
	"github.com/michaelvl/artifact-underwriter/internal/policy"
	"github.com/michaelvl/artifact-underwriter/internal/vsa"
	"github.com/spf13/cobra"
)

func EvaluatePolicyCmd() *cobra.Command {
	opts := options.EvaluateOptions{}

	cmd := &cobra.Command{
		Use:   "evaluate-policy <oci-artifact-ref>",
		Short: "Evaluate policy against OCI artifact",
		Args:       cobra.MinimumNArgs(1),
		ArgAliases: []string{"oci-artifact-ref"},
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("evaluate %v\n", args[0])

			pol, err := policy.Load("examples/container-policy.yaml")
			if err != nil {
				return err
			}

			atts, statements, err := attestations.GetAttestations(context.Background(), args[0], pol)
			if err != nil {
				return err
			}
			if opts.OutputAttestationsPath != "" {
				attestations.WriteAttestations(statements, opts.OutputAttestationsPath)
			}
			err = policy.Evaluate(pol, statements)
			if err != nil {
				return err
			}

			vsa.Generate(atts, "PASSED")

			return nil
		},
	}

	opts.AddFlags(cmd)
	return cmd
}
