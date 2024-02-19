package options

import (
	"github.com/spf13/cobra"
)

type EvaluateOptions struct {
	OutputAttestationsPath string
}

func (o *EvaluateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.OutputAttestationsPath, "output-attestations", "",
		"path to write raw attestation json to")
}
