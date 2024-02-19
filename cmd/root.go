package cmd

import (
	"github.com/michaelvl/artifact-underwriter/internal/build"

	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:     "artifact-underwriter",
		Version: build.Version,
		Short:   "A tool for evaluating artifacts and create in-toto attestations",
	}
	rootCmd.SetVersionTemplate("{{.Version}}")

	rootCmd.AddCommand(
		VersionCmd(),
		EvaluatePolicyCmd(),
	)

	return rootCmd
}
