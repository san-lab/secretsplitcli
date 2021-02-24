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
	Run:   readKeyfile2,
}

func readKeyfile2(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		fmt.Println("missing or ambiguous filename")
		return
	}
	ReadKeyfile(args[0])
}

func ReadKeyfile(filename string) (*goethkey.Keyfile, error) {
	pass, err := goethkey.ReadPassword("Keyfile password:")
	if err != nil {
		return nil, err
	}
	keyfile, err := goethkey.ReadKeyfile(pass, filename)
	if err != nil {
		return nil, err
	}

	//TODO Handle the unencrypted kyefiles

	//derive the key from password
	var key []byte
	switch keyfile.Crypto.Kdf {
	case "scrypt":
		var macok bool
		key, macok = handleScrypt(keyfile, pass)
		if !macok {
			return nil, fmt.Errorf("MAC wrong")
		}

	default:

		return nil, fmt.Errorf("Unsupported KDF: ", keyfile.Crypto.Kdf)
	}
	plaintext, err := decrypt(keyfile, key)
	keyfile.Plaintext = plaintext
	return keyfile, err
}

//This assumes that the MAC verification has been OK
func decrypt(kf *goethkey.Keyfile, key []byte) (privkey []byte, err error) {

	privkey, err = goethkey.Decrypt(kf, key)
	if err != nil {
		err = fmt.Errorf("Not implemented cipher: %s\n", kf.Crypto.Cipher)
		return
	}

	prv, pubkeyec := btcec.PrivKeyFromBytes(btcec.S256(), privkey)
	pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)
	fmt.Printf("Public key: \t%s\n", hex.EncodeToString(pubkeyeth))
	if goethkey.Verbose {
		fmt.Printf("Private key: \t%s\n", hex.EncodeToString(privkey))
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

func handleScrypt(kf *goethkey.Keyfile, pass []byte) (key []byte, macok bool) {

	//derive key
	key, err := goethkey.KeyFromPassScrypt(pass, kf.Crypto.KdfScryptParams)
	if err != nil {
		fmt.Println(err)
		return
	}

	//read the ciphertext
	citx, err := hex.DecodeString(kf.Crypto.Ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}

	//verify mac
	mymac := hex.EncodeToString(goethkey.Keccak256(append(key[16:32], citx...)))
	macok = (mymac == kf.Crypto.Mac)
	fmt.Printf("\nMAC verification: %v\n\n", macok)

	return key, macok
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
