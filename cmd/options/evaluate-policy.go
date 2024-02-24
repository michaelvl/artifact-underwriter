package options

import (
	"github.com/spf13/cobra"
)

type EvaluateOptions struct {
	PolicyPath                  string
	OutputAttestationsPath      string
	OutputVsaPath               string
	FailOnPolicyValidationError bool
}

func (o *EvaluateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.PolicyPath, "policy", "",
		"policy file to evaluate against")
	cobra.CheckErr(cmd.MarkFlagRequired("policy"))
	cmd.Flags().StringVar(&o.OutputAttestationsPath, "output-attestations", "",
		"path to write raw attestation json to")
	cmd.Flags().StringVar(&o.OutputVsaPath, "output-vsa", "",
		"path to write verification-statement attestation to")
	cmd.Flags().BoolVar(&o.FailOnPolicyValidationError, "fail-on-validation-error", false,
		"exit with non-zero exit code if policy verification fail")
}
