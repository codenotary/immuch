/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup your configuration",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("configuration set")
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)

	// Here you will define your flags and configuration settings.
	setupCmd.PersistentFlags().StringVar(&vaultKey, "vault-key", "", "ImmuDB Vault API key")
	setupCmd.PersistentFlags().StringVar(&encKeyAes, "enc-aes", "", "Optional encryption key for encrypting your messages with AES symmetric encryption")
	setupCmd.PersistentFlags().StringVar(&encKeyPgpPub, "enc-pgp-pub", "", "Optional path to encryption key for encrypting your messages with PGP public/private key infrastructure")
	setupCmd.PersistentFlags().StringVar(&encKeyPgpPriv, "enc-pgp-priv", "", "Optional path to encryption key for encrypting your messages with PGP public/private key infrastructure")
	setupCmd.PersistentFlags().StringVar(&encKeyPgpPassphrase, "enc-pgp-passphrase", "", "Passphrase for your PGP key")
	setupCmd.PersistentFlags().StringVar(&identity, "identity", "", "Your identity / name")

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// setupCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// setupCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
