package main

import "github.com/spf13/cobra"

func main() {
	var rootCmd = &cobra.Command {
		Use:   "tlst [flags] [commands]",
		Short: "TLS playground",
	}

	var serverCmd = &cobra.Command {
		Use:   "server [bind_address] [flags]",
		Short: "TLS server",
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cert, _ := cmd.Flags().GetString("certificate")
			key, _ := cmd.Flags().GetString("key")
			server(args[0], cert, key)
		},
	}
	serverCmd.Flags().StringP("certificate", "c", "server-cert.pem", "PEM file with certificate")
	serverCmd.Flags().StringP("key", "k", "server-private.pem", "PEM file with key")
	rootCmd.AddCommand(serverCmd)

	var clientCmd = &cobra.Command {
		Use:   "client [address] [flags]",
		Short: "TLS client",
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cert, _ := cmd.Flags().GetString("certificate")
			key, _ := cmd.Flags().GetString("key")
			client(args[0], cert, key)
		},
	}
	clientCmd.Flags().StringP("certificate", "c", "client-cert.pem", "PEM file with certificate")
	clientCmd.Flags().StringP("key", "k", "client-private.pem", "PEM file with key")
	rootCmd.AddCommand(clientCmd)


	var keygenCmd = &cobra.Command {
		Use:   "keygen",
		Short: "generate some keys",
		Run: func(cmd *cobra.Command, args []string) {
			keygen()
		},
	}
	rootCmd.AddCommand(keygenCmd)

	var signjCmd = &cobra.Command {
		Use:   "create-cert [csr] [public-key] [out-name]",
		Short: "create certificate from json csr",
		Args: cobra.MinimumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			cert, _ := cmd.Flags().GetString("ca-certificate")
			sign_json_csr(args[0], args[1], args[2], cert)
		},
	}
	signjCmd.Flags().StringP("ca-certificate", "c", "ca-cert.pem", "PEM file with ca certificate")
	rootCmd.AddCommand(signjCmd)

	var genKeyCmd = &cobra.Command {
		Use:   "gen-key [name]",
		Short: "generate key",
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generate_and_store_key(args[0])
		},
	}
	rootCmd.AddCommand(genKeyCmd)

	var testCmd = &cobra.Command {
		Use:   "test",
		Short: "develtest",
		Run: func(cmd *cobra.Command, args []string) {
			test()
		},
	}
	rootCmd.AddCommand(testCmd)

	rootCmd.Execute()
}