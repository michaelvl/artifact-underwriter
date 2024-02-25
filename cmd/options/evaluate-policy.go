package options

import (
	"github.com/spf13/cobra"
)

type EvaluateOptions struct {
	PolicyPath                  string
	OutputAttestationsPath      string
	OutputVsaPath               string
	OutputVsaPredicatePath      string
	FailOnPolicyValidationError bool
	SlsaVsaPassVerifiedLevel    string
	VerifierID                  string
}

func (o *EvaluateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.PolicyPath, "policy", "",
		"policy file to evaluate against")
	cobra.CheckErr(cmd.MarkFlagRequired("policy"))
	cmd.Flags().StringVar(&o.OutputAttestationsPath, "output-attestations", "",
		"path to write raw attestation json to")
	cmd.Flags().StringVar(&o.OutputVsaPath, "output-vsa", "",
		"path to write verification-statement attestation to")
	cmd.Flags().StringVar(&o.OutputVsaPredicatePath, "output-vsa-predicate", "",
		"path to write verification-statement predicate to")
	cmd.Flags().BoolVar(&o.FailOnPolicyValidationError, "fail-on-validation-error", false,
		"exit with non-zero exit code if policy verification fail")
	cmd.Flags().StringVar(&o.SlsaVsaPassVerifiedLevel, "vsa-verified-level", "SLSA_BUILD_LEVEL_3",
		"SLSA verification level to insert into VSA")
	cmd.Flags().StringVar(&o.VerifierID, "verifier-id", "github.com/michaelvl/artifact-underwriter",
		"Verifier ID to insert into VSA")
}
