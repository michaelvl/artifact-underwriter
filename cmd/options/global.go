package options

import (
	"github.com/spf13/cobra"
)

type GlobalOptions struct {
	Verbose bool
}

func (o *GlobalOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(&o.Verbose, "verbose", "d", false, "enable verbose logging")
}
