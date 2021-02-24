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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/san-lab/secretsplitcli/goethkey"
	"github.com/spf13/cobra"
)

// generateKeyfileCmd represents the generateKeyfile command
var generateKeyfileCmd = &cobra.Command{
	Use:   "generateKeyfile filename",
	Short: "Generate a new keyfile",
	Long:  `Generates a new keyfile. Interactively asks for password (do not forget your choice!).`,
	Run:   generateKeyfile,
}

var genFilename string
var kdf string

func generateKeyfile(cmd *cobra.Command, args []string) {
	if len(args) == 1 {
		genFilename = args[0]
	} else {
		genFilename = time.Now().Format(time.RFC3339) + ".json"
	}

	kf := goethkey.Keyfile{}

	kf.Crypto.Kdf = kdf

	pass, err := goethkey.SetPassword()
	if err != nil {
		fmt.Println(err)
		return
	}

	//for len(pass) <

	//Generate the Koblitz private key
	ethkey := make([]byte, 32)
	rand.Read(ethkey)

	salt := make([]byte, 16)
	rand.Read(salt)
	/*
		kf.Crypto.KdfparamsPack.Dklen=32
		kf.Crypto.KdfparamsPack.N=131072
		kf.Crypto.KdfparamsPack.P=1
		kf.Crypto.KdfparamsPack.R=8
		kf.Crypto.KdfparamsPack.Salt=hex.EncodeToString(salt)
	*/
	switch kdf {
	case "scrypt":
		kf.Crypto.KdfScryptParams.Dklen = 32
		kf.Crypto.KdfScryptParams.N = 131072
		kf.Crypto.KdfScryptParams.P = 1
		kf.Crypto.KdfScryptParams.R = 8
		kf.Crypto.KdfScryptParams.Salt = hex.EncodeToString(salt)
	default:
		fmt.Println("Unsupported KDF scheme")
		return
	}

	err = goethkey.EncryptAES128(&kf, ethkey, pass)
	if err != nil {
		fmt.Println(err)
		return
	}

	x, y := btcec.S256().ScalarBaseMult(ethkey)
	pubkeyeth := append(x.Bytes(), y.Bytes()...)
	fmt.Printf("Public key: %s\n", hex.EncodeToString(pubkeyeth))
	kecc := goethkey.Keccak256(pubkeyeth)
	addr := kecc[12:]

	kf.Address = hex.EncodeToString(addr)

	bytes, err := json.Marshal(&kf)
	if err != nil {
		fmt.Println(err)
		return
	}
	ioutil.WriteFile(genFilename, bytes, 0644)
}

func init() {
	rootCmd.AddCommand(generateKeyfileCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// generateKeyfileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// generateKeyfileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	generateKeyfileCmd.Flags().StringVarP(&kdf, "kdf", "", "scrypt", "--kdf preferredKDF")
}
