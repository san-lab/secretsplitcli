/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"encoding/hex"

	"github.com/btcsuite/btcd/btcec"
	"github.com/san-lab/secretsplitcli/goethkey"
	"github.com/spf13/cobra"
)

// readKeyfileCmd represents the readKeyfile command
var readKeyfileCmd = &cobra.Command{
	Use:   "readKeyfile filename",
	Short: "Read an Ethereum key file",
	Long:  `A longer description will follow soon.`,
	Run:   readKeyfile,
}

func readKeyfile(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		fmt.Println("missing or ambiguous filename")
		return
	}
	kf, err := goethkey.ReadAndProcessKeyfile(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	prv, pubkeyec := btcec.PrivKeyFromBytes(btcec.S256(), kf.Plaintext)
	pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)
	fmt.Printf("Public key: \t%s\n", hex.EncodeToString(pubkeyeth))
	if goethkey.Verbose {
		fmt.Printf("Private key: \t%s\n", hex.EncodeToString(kf.Plaintext))
		fmt.Println("D:", prv.D)
		fmt.Println("X:", pubkeyec.X)
		fmt.Println("Y:", pubkeyec.Y)
	}
	kecc := goethkey.Keccak256(pubkeyeth)
	addr := kecc[12:]
	fmt.Printf("Ethereum addr: %s\n", hex.EncodeToString(addr))
	fmt.Printf("(in file: %s)\n", kf.Address)
	return
}

func init() {
	rootCmd.AddCommand(readKeyfileCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// readKeyfileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// readKeyfileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
