package cmd

import (
	"context"

	"github.com/michaelvl/artifact-underwriter/cmd/options"
	"github.com/michaelvl/artifact-underwriter/internal/attestations"
	"github.com/michaelvl/artifact-underwriter/internal/oci"
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
			pol, err := policy.Load("examples/container-policy.yaml")
			if err != nil {
				return err
			}

			digest, err := oci.ResolveDigest(args[0])
			if err != nil {
				return err
			}
			atts, statements, err := attestations.GetAttestations(context.Background(), digest, pol)
			if err != nil {
				return err
			}
			if opts.OutputAttestationsPath != "" {
				attestations.WriteStatements(statements, opts.OutputAttestationsPath)
			}
			err = policy.Evaluate(pol, statements)
			if err != nil {
				return err
			}

			if opts.OutputVsaPath != "" {
				vsa, err := vsa.Generate(digest, atts, "PASSED")
				if err != nil {
					return err
				}
				err = attestations.WriteStatement(vsa, opts.OutputVsaPath)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	opts.AddFlags(cmd)
	return cmd
}
