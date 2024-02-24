package cmd

import (
	"io"
	"log"

	"github.com/michaelvl/artifact-underwriter/cmd/options"
	"github.com/michaelvl/artifact-underwriter/internal/build"

	"github.com/spf13/cobra"
)

var (
	globalOpts = &options.GlobalOptions{}
)

func New() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:     "artifact-underwriter",
		Version: build.Version,
		Short:   "A tool for evaluating artifacts and create in-toto attestations",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			log.SetFlags(log.Ltime | log.Lmicroseconds)
			if !globalOpts.Verbose {
				log.SetOutput(io.Discard)
			}
			return nil
		},
	}
	rootCmd.SetVersionTemplate("{{.Version}}")
	globalOpts.AddFlags(rootCmd)

	rootCmd.AddCommand(
		VersionCmd(),
		EvaluatePolicyCmd(),
	)

	return rootCmd
}
