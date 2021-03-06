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
	numShares = 1

	var arrayShareBytes [][]byte
	var filename string
	var groupID string

	for i := 0; i < numShares; i++ {
		fmt.Print("Enter the name of share " + strconv.Itoa(i+1) + ": ")
		fmt.Scanf("%s", &filename)
		keyfile, err := goethkey.ReadAndProcessKeyfile(filename)
		if err != nil {
			fmt.Println(err)
			return
		}
		id := keyfile.ID
		if i == 0 {
			numSharesHex := id[8:10]
			numShares64, _ := strconv.ParseInt(numSharesHex, 16, 64)
			numShares = int(numShares64)
			groupID = id[13:]
			fmt.Println("Stored group ID: ", groupID)
		}
		if i > 0 && id[13:] != groupID {
			fmt.Println("Error this share does not belong to the same group as the previous ones, try again")
			i--
		} else {
			arrayShareBytes = append(arrayShareBytes, keyfile.Plaintext)
		}
	}

	var sharesOut []*share.PriShare
	for _, b := range arrayShareBytes {

		ps, err := goethkey.Deserialize(b)
		if err != nil {
			fmt.Println(err)
			return
		}
		sharesOut = append(sharesOut, ps)
	}

	rec, _ := share.RecoverSecret(pairing.NewSuiteBn256().G2(), sharesOut, minShares, minShares)
	pubrec := pairing.NewSuiteBn256().G2().Point().Mul(rec, nil)
	b, _ := rec.MarshalBinary()
	pbb, _ := pubrec.MarshalBinary()
	retrievedKey := hex.EncodeToString(b)
	retPubKey := hex.EncodeToString(pbb)
	fmt.Printf("Private key: \t%s\n", retrievedKey)
	fmt.Printf("Public key: \t%s\n", retPubKey)
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
