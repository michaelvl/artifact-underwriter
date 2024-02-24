package cmd

import (
	"context"
	"fmt"
	"log"

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
		Use:        "evaluate-policy <oci-artifact-ref>",
		Short:      "Evaluate policy against OCI artifact",
		Args:       cobra.MinimumNArgs(1),
		ArgAliases: []string{"oci-artifact-ref"},
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Printf("loading policy %v\n", opts.PolicyPath)
			pol, err := policy.Load(opts.PolicyPath)
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
				err = attestations.WriteStatements(statements, opts.OutputAttestationsPath)
				if err != nil {
					return err
				}
			}
			allowed, err := policy.Evaluate(pol, statements)
			if err != nil {
				return err
			}
			var allowedText = "FAILED"
			if allowed {
				allowedText = "PASSED"
			}
			log.Printf("policy evaluation status: %v\n", allowedText)

			if opts.OutputVsaPath != "" {
				vsa, err := vsa.Generate(digest, atts, allowedText)
				if err != nil {
					return err
				}
				err = attestations.WriteStatement(vsa, opts.OutputVsaPath)
				if err != nil {
					return err
				}
			}

			if opts.FailOnPolicyValidationError {
				return fmt.Errorf("validation failed")
			}
			return nil
		},
	}

	opts.AddFlags(cmd)
	return cmd
}
