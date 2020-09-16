package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh/terminal"
)

func handleError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getPass() []byte {
	fmt.Print("Passphrase: ")
	pass, err := terminal.ReadPassword(0)
	handleError(err)

	return pass
}

func hashKey(pass []byte) []byte {
	h := sha256.New()
	if _, err := h.Write(pass); err != nil {
		fmt.Println("Error while hashing passphrase")
		os.Exit(1)
	}
	return h.Sum(nil)
}

func encCMD(dirname string) {
	text := new(bytes.Buffer)
	zipF(dirname, text)

	key := hashKey(getPass())
	c, err := aes.NewCipher(key)
	handleError(err)

	gcm, err := cipher.NewGCM(c)
	handleError(err)

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	handleError(err)

	err = ioutil.WriteFile(dirname+".encrypted", gcm.Seal(nonce, nonce, text.Bytes(), nil), 0600)
	handleError(err)

}

func decCMD(dirname string) {
	text, err := ioutil.ReadFile(dirname)
	handleError(err)

	key := hashKey(getPass())
	c, err := aes.NewCipher(key)
	handleError(err)

	gcm, err := cipher.NewGCM(c)
	handleError(err)

	nonceSize := gcm.NonceSize()
	if len(text) < nonceSize {
		fmt.Println(err)
	}

	nonce, text := text[:nonceSize], text[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, text, nil)
	handleError(err)

	r, err := zip.NewReader(bytes.NewReader(plaintext), int64(len(plaintext)))
	handleError(err)
	unzipF(r)
}

func unzipCMD(dirname string) {
	r, err := zip.OpenReader(dirname)
	handleError(err)
	defer r.Close()
	unzipF(&r.Reader)
}

func unzipF(r *zip.Reader) {
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			fmt.Printf("Error opening file %s: %v\n", f.Name, err)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(f.Name), 0744); err != nil {
			fmt.Println(err)
			continue
		}

		file, err := os.Create(f.Name)
		if err != nil {
			fmt.Printf("Error creating file %s\n", f.Name)
			continue
		}

		if _, err := io.Copy(file, rc); err != nil {
			fmt.Printf("Error copying content to file %s\n", f.Name)
			continue
		}

		rc.Close()
		file.Close()
	}
}

func zipF(dirname string, dest io.Writer) {
	w := zip.NewWriter(dest)
	err := filepath.Walk(dirname, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		} else if !info.IsDir() {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			f, err := w.Create(path)
			if err != nil {
				return err
			}
			if _, err := f.Write(content); err != nil {
				return err
			}
		}
		return nil
	})
	handleError(err)
	err = w.Close()
	handleError(err)
}

func zipCMD(dirname string) {
	dest, err := os.Create(dirname + ".zip")
	handleError(err)

	zipF(dirname, dest)
}

func main() {
	if len(os.Args) == 3 {
		switch os.Args[1] {
		case "zip":
			zipCMD(os.Args[2])
		case "unzip":
			unzipCMD(os.Args[2])
		case "enc":
			encCMD(os.Args[2])
		case "dec":
			decCMD(os.Args[2])
		default:
			fmt.Println("Unknown command:", os.Args[1])
		}
	} else {
		fmt.Println("USAGE: secure (zip|unzip|enc|dec) <file>")
		os.Exit(1)
	}
}
