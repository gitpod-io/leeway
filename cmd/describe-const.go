package cmd

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// describeConstCmd represents the describeTree command
var describeConstCmd = &cobra.Command{
	Use:   "const",
	Short: "Prints the value of a component constant",
	Run: func(cmd *cobra.Command, args []string) {
		comp, _, exists := getTarget(args)
		if !exists {
			log.Fatal("const needs a component")
		}

		sp, _ := cmd.Flags().GetString("constant")
		if sp != "" {
			val, ok := comp.Constants[sp]
			if !ok {
				os.Exit(1)
			}

			fmt.Println(val)
			os.Exit(0)
		}

		for k, v := range comp.Constants {
			fmt.Printf("%s=%s\n", k, v)
		}
	},
}

func init() {
	describeCmd.AddCommand(describeConstCmd)

	describeConstCmd.Flags().StringP("constant", "n", "", "Name of the constant whose value to print")
}
