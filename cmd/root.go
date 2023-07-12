/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var vaultKey string
var encKeyAes string
var encKeyPgpPub string
var encKeyPgpPriv string
var encKeyPgpPassphrase string
var identity string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "immuch",
	Short: "A secure CLI messager making use of ImmuDB Vault as a backend",
	Long: `ImmuCh is a secure CLI messager making use of ImmuDB Vault as a backend:

It enable two parties to communicate securely by using a trusted central authority for exchanging their messages.

immudb Vault guarantees integrity of contents saved by a mathematical proof.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.immuch.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".go-immuch" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".immuch")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	if vaultKey != "" {
		viper.Set("VAULT_KEY", vaultKey)
	}

	if encKeyAes != "" {
		viper.Set("ENC_KEY_AES", encKeyAes)
	}

	if encKeyPgpPub != "" {
		viper.Set("ENC_KEY_PGP_PUB", encKeyPgpPub)
	}

	if encKeyPgpPriv != "" {
		viper.Set("ENC_KEY_PGP_PRIV", encKeyPgpPriv)
	}

	if encKeyPgpPassphrase != "" {
		viper.Set("ENC_KEY_PGP_PASSPHRASE", encKeyPgpPassphrase)
	}

	if identity != "" {
		viper.Set("IDENTITY", identity)
	}

	if vaultKey != "" || encKeyAes != "" || encKeyPgpPub != "" || encKeyPgpPriv != "" || encKeyPgpPassphrase != "" || identity != "" {
		if viper.ConfigFileUsed() != "" {
			viper.WriteConfigAs(viper.ConfigFileUsed())
		} else {
			viper.SafeWriteConfig()
		}
	}

}
