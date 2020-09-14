package main

import (
	"archive/zip"
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

func getPass() []byte {
	fmt.Print("Passphrase: ")
	pass, err := terminal.ReadPassword(0)
	if err != nil {
		fmt.Println("Could not read password")
		os.Exit(1)
	}

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

func encCMD(filename string) {
	text, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file", filename)
		os.Exit(1)
	}

	key := hashKey(getPass())
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error generating a cipher")
		os.Exit(1)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println("Error generating GCM")
		os.Exit(1)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := ioutil.WriteFile(filename+".encrypted", gcm.Seal(nonce, nonce, text, nil), 0600); err != nil {
		fmt.Println("Error writing to file")
		os.Exit(1)
	}
}

func decCMD(filename string) {
	text, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file", filename)
		os.Exit(1)
	}

	key := hashKey(getPass())
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error generating a cipher")
		os.Exit(1)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println("Error generating GCM")
		os.Exit(1)
	}
	nonceSize := gcm.NonceSize()
	if len(text) < nonceSize {
		fmt.Println(err)
	}

	nonce, text := text[:nonceSize], text[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, text, nil)
	if err != nil {
		fmt.Println(err)
	}

	if err := ioutil.WriteFile("out.txt", plaintext, 0600); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func unzipCMD(filename string) {
	r, err := zip.OpenReader(filename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer r.Close()

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

func zipCMD(dirname string) {
	dest, err := os.Create(dirname + ".zip")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	w := zip.NewWriter(dest)
	err = filepath.Walk(dirname, func(path string, info os.FileInfo, err error) error {
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
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = w.Close()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) == 3 {
		cmd := os.Args[1]
		switch cmd {
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
