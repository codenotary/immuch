/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	b64 "encoding/base64"

	"github.com/spf13/viper"
	"golang.org/x/crypto/openpgp"

	"github.com/spf13/cobra"
)

type EncType string

const (
	AES EncType = "AES"
	PGP EncType = "PGP"
)

type ImmuMsg struct {
	Author  string
	Message string
	Enc     EncType
}

var encryptAes bool
var encryptPgp bool

// sendCmd represents the send command
var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send out an immutable message",
	Long:  `This command will send/store your message in ImmuDB Vault encrypted by choice in AES, with PGP or in plaintext based on your settings and args passed.`,
	Run: func(cmd *cobra.Command, args []string) {

		var msg string
		if len(args) >= 1 && args[0] != "" {
			msg = args[0]

			var identity = "anonymous"
			if viper.Get("IDENTITY") != nil {
				identity = viper.GetString("IDENTITY")
			}

			msgObj := ImmuMsg{
				Author:  identity,
				Message: msg,
			}

			if encryptAes {
				if viper.Get("ENC_KEY_AES") != nil {
					debug("Using AES")
					msgObj.Message = b64.StdEncoding.EncodeToString([]byte(doEncryptAes(msg, viper.GetString("ENC_KEY_AES"))))
					msgObj.Enc = AES
					debug("Encrypted Secret: " + msgObj.Message)
				} else {
					fmt.Println("AES key not set. Aborting.")
					os.Exit(1)
				}

			} else if encryptPgp {
				if viper.Get("ENC_KEY_PGP_PUB") != nil {
					debug("Using PGP")
					var crypt, err = encPgp(msg, viper.GetString("ENC_KEY_PGP_PUB"))
					if err != nil {
						fmt.Println("something went wrong", err)
					} else {
						msgObj.Message = crypt
						msgObj.Enc = PGP
					}

				} else {
					fmt.Println("PGP PUB key not set. Aborting.")
					os.Exit(1)
				}
			} else {
				log.Println("!!! sending in plain text")
			}

			// fmt.Println("Putting msg '" + msg + "' to vault")

			// initialize http client
			client := &http.Client{}

			debug("Formatting final object payload")
			// marshal User to json
			json, err := json.Marshal(msgObj)
			if err != nil {
				panic(err)
			}

			debug("Sending to Vault")
			// set the HTTP method, url, and request body
			req, err := http.NewRequest(http.MethodPut, "https://vault.immudb.io/ics/api/v1/ledger/default/collection/default/document", bytes.NewBuffer(json))
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

			// fmt.Println(resp.StatusCode)
			if resp.StatusCode == 200 {
				dt := time.Now().Format(time.RFC850)
				fmt.Println(dt, "sent:", msgObj.Author, "--->", msg)
			} else {
				b, err := io.ReadAll(resp.Body)
				// b, err := ioutil.ReadAll(resp.Body)  Go.1.15 and earlier
				if err != nil {
					debug(err.Error())
				}
				debug("The message was not delivered: " + string(b))
			}

		} else {
			println("No message specified")
			os.Exit(1)
		}

	},
}

func init() {
	rootCmd.AddCommand(sendCmd)

	// Here you will define your flags and configuration settings.
	sendCmd.PersistentFlags().BoolVar(&encryptAes, "encrypt-aes", false, "Encrypt with AES symmetric key")
	sendCmd.PersistentFlags().BoolVar(&encryptPgp, "encrypt-pgp", false, "Encrypt with PGP public key")
}

func doEncryptAes(msg string, secret string) []byte {
	text := []byte(msg)
	key := []byte(secret)

	debug("Generating a new AES cipher with provided key")
	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	debug("Encrypting the message: " + msg)
	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	return gcm.Seal(nonce, nonce, text, nil)
}

func encPgp(secretString string, publicKeyring string) (string, error) {
	debug("Reading public key from" + publicKeyring)
	// Read in public key
	keyringFileBuffer, _ := os.Open(publicKeyring)
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		debug("Failed reading public key: " + err.Error())
		return "", err
	}

	debug("Encrypting message: " + secretString)
	// encrypt string
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write([]byte(secretString))
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}

	debug("Encoding to base64")
	// Encode to base64
	bytes, err := ioutil.ReadAll(buf)
	if err != nil {
		return "", err
	}
	encStr := base64.StdEncoding.EncodeToString(bytes)

	// Output encrypted/encoded string
	debug("Encrypted Secret: " + encStr)

	return encStr, nil
}
