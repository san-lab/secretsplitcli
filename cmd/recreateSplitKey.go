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
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/san-lab/secretsplitcli/goethkey"
	"github.com/spf13/cobra"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
)

// readKeyfileCmd represents the readKeyfile command
var recreateSplitKeyCmd = &cobra.Command{
	Use:   "recreateSplitKey",
	Short: "Read an Ethereum key file",
	Long:  `A longer description will follow soon.`,
	Run:   recreateSplitKey,
}

func recreateSplitKey(cmd *cobra.Command, args []string) {
	var numShares int
	fmt.Print("Enter the number of shares to be used: ")
	fmt.Scanf("%d", &numShares)
	fmt.Print("\n")

	var arrayShareBytes [][]byte

	for i := 0; i < numShares; i++ {
		var filename string
		fmt.Print("Enter the name of share " + strconv.Itoa(i+1) + ": ")
		fmt.Scanf("%s", &filename)
		keyfile, err := ReadAndProcessKeyfile(filename)
		if err != nil {
			fmt.Println(err)
			return
		}
		arrayShareBytes = append(arrayShareBytes, keyfile.Ciphertext)
	}

	var sharesOut []*share.PriShare
	for _, b := range arrayShareBytes {
		s2 := new(sharePrishare)
		s2.UnmarshalJSON(b)
		sharesOut = append(sharesOut, &share.PriShare{s2.I, s2.V})
	}

	rec, _ := share.RecoverSecret(pairing.NewSuiteBn256().G1(), sharesOut, minShares, minShares)
	b, _ := rec.MarshalBinary()
	retrievedKey := hex.EncodeToString(b)
	fmt.Printf("Private key: \t%s\n", retrievedKey)
}

func ReadAndProcessKeyfile(filename string) (keyfile *goethkey.Keyfile, err error) {
	keyfile, err = goethkey.ReadKeyfile(filename)
	if err != nil {
		return
	}

	//TODO Handle the unencrypted kyefiles

	//derive the key from password
	var key []byte
	switch keyfile.Crypto.Kdf {
	case "scrypt":
		var macok bool
		key, macok = handleScrypt(keyfile)
		if !macok {
			return
		}

	default:
		err = fmt.Errorf("Unsupported KDF: " + keyfile.Crypto.Kdf)
		return
	}
	err = decryptAndReturn(keyfile, key)
	return
}

//This assumes that the MAC verification has been OK
func decryptAndReturn(kf *goethkey.Keyfile, key []byte) (err error) {
	switch strings.ToLower(kf.Crypto.Cipher) {
	case "aes-128-ctr":
		kf.Ciphertext, err = decryptAES128CTR(kf, key)
	default:
		err = fmt.Errorf("Not implemented cipher: %s\n", kf.Crypto.Cipher)
		return
	}

	return nil
}

func init() {
	rootCmd.AddCommand(recreateSplitKeyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// readKeyfileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// readKeyfileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
