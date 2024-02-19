package cmd

import (
	"context"
	"fmt"

	"github.com/michaelvl/artifact-underwriter/cmd/options"
	"github.com/michaelvl/artifact-underwriter/internal/policy"
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

			err = pol.Evaluate(context.Background(), args[0], opts.OutputAttestationsPath)
			if err != nil {
				return err
			}

			return nil
		},
	}

	opts.AddFlags(cmd)
	return cmd
}
