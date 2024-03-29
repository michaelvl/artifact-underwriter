package cmd

import (
	"github.com/michaelvl/artifact-underwriter/internal/build"

	"github.com/spf13/cobra"
)

func VersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			println(build.Version)
		},
	}
}
