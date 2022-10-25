package util

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	gitSHA    = "unknown"
	gitBranch = "unknown"
	gitTag    = "unknown"
	buildDate = "unknown"
)

func NewCommandVersion() *cobra.Command {
	cmd := &cobra.Command{
		Use: "version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Build Date: %s\n", buildDate)
			fmt.Printf("Git SHA/Branch/Tag: %s/%s/%s\n", gitSHA, gitBranch, gitTag)
			fmt.Printf("Go Version/OS/Arch: %s/%s/%s\n",
				runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
	return cmd
}

// VersionGitSHA returns Git hash string
func VersionGitSHA() string {
	return gitSHA
}

// VersionGitTag returns Git tag string
func VersionGitTag() string {
	return gitTag
}

// VersionGitBranch returns current Git branch name
func VersionGitBranch() string {
	return gitBranch
}

// VersionBuildDate returns date when your binary is built
func VersionBuildDate() string {
	return buildDate
}
