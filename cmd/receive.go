/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/openpgp"
)

// type ImmuSearch struct {
// 	page    int
// 	perPage int
// }

type ImmuResp struct {
	Page      int             `json:"page"`
	PerPage   int             `json:"perPage"`
	Revisions []ImmuRevisions `json:"revisions"`
	SearchId  string          `json:"searchId"`
}

type ImmuRevisions struct {
	Document ImmuDocument `json:"document"`
}

type ImmuDocument struct {
	Author        string      `json:"Author"`
	Message       string      `json:"Message"`
	EncType       string      `json:"Enc"`
	Id            string      `json:"_id"`
	Vault_md      ImmuVaultMd `json:"_vault_md"`
	Revision      string      `json:"revision"`
	TransactionId string      `json:"transactionId"`
}

type ImmuVaultMd struct {
	Creator string `json:"creator"`
	Ts      int    `json:"ts"`
}

// receiveCmd represents the receive command
var receiveCmd = &cobra.Command{
	Use:   "receive",
	Short: "Receive an immutable message",
	Long:  `This command will receive the last posted message in your ImmuDB/Cloud account and decrypt based on the encryption set when it was sent`,
	Run: func(cmd *cobra.Command, args []string) {
		// initialize http client
		client := &http.Client{}

		var jsonData = []byte(`{
			"page": 1,
			"perPage": 100,
			"desc": 1
		}`)

		// fmt.Println("json:", jsonData)

		// set the HTTP method, url, and request body
		req, err := http.NewRequest("POST", "https://vault.immudb.io/ics/api/v1/ledger/default/collection/default/documents/search", bytes.NewBuffer(jsonData))
		if err != nil {
			panic(err)
		}

		// set the request header Content-Type for json
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("X-API-Key", viper.GetString("VAULT_KEY"))
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}

		body, _ := ioutil.ReadAll(resp.Body)

		if resp.StatusCode == 200 {
			var immuResp ImmuResp
			var err = json.Unmarshal(body, &immuResp)
			if err != nil {
				fmt.Println("Error during unmarshal: ", err)
			}

			var lastIdx = len(immuResp.Revisions) - 1
			if lastIdx < 0 {
				fmt.Println("nothing to receive. probably there are no messages yet")
				os.Exit(1)
			}
			i, err := strconv.ParseInt(strconv.Itoa(immuResp.Revisions[lastIdx].Document.Vault_md.Ts), 10, 64)
			if err != nil {
				panic(err)
			}
			var msg = ""
			if immuResp.Revisions[lastIdx].Document.EncType == string(AES) {
				if viper.Get("ENC_KEY_AES") != nil {
					debug("Decrypting with AES")
					var decoded, err = b64.StdEncoding.DecodeString(immuResp.Revisions[lastIdx].Document.Message)
					if err != nil {
						fmt.Println(err)
					}
					msg = doDecryptAes(string(decoded), viper.GetString("ENC_KEY_AES"))
				} else {
					fmt.Println("AES key not set. Aborting.")
					os.Exit(1)
				}
			} else if immuResp.Revisions[lastIdx].Document.EncType == string(PGP) {
				if viper.Get("ENC_KEY_PGP_PRIV") != nil {
					if viper.Get("ENC_KEY_PGP_PASSPHRASE") != nil {
						debug("Decrypting with PGP")
						var decrypted, err = decPgp(immuResp.Revisions[lastIdx].Document.Message, viper.GetString("ENC_KEY_PGP_PRIV"))
						if err != nil {
							fmt.Println(err)
						}
						msg = decrypted
					} else {
						fmt.Println("Passphrase for PGP Private key not set. Aborting.")
						os.Exit(1)
					}
				} else {
					fmt.Println("PGP Private key not set. Aborting.")
					os.Exit(1)
				}
			} else {
				msg = immuResp.Revisions[lastIdx].Document.Message
			}

			var time = time.Unix(i, 0).Format(time.RFC850)
			fmt.Println(time, "received:", immuResp.Revisions[lastIdx].Document.Author, "--->", msg)
		} else {
			fmt.Println("something did not work out. probably there are no messages")
		}
	},
}

func init() {
	rootCmd.AddCommand(receiveCmd)
}

func doDecryptAes(msg string, secret string) string {
	key := []byte(secret)
	ciphertext := []byte(msg)

	debug("Loading the AES key")
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	debug("Decrypting the message")
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return string(plaintext)
}

func decPgp(encString string, secretKeyring string) (string, error) {
	var passphrase = viper.GetString("ENC_KEY_PGP_PASSPHRASE")

	// init some vars
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	debug("Loading the private key: " + secretKeyring)
	// Open the private key file
	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		return "", err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	entity = entityList[0]

	debug("Decrypting private key with the provided passphrase")
	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	passphraseByte := []byte(passphrase)
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	debug("Decoding base64")
	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encString)
	if err != nil {
		return "", err
	}

	debug("Decrypting the message")
	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}
