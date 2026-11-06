package run

import (
	"crypto"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const sshKeyPassphraseAttempts = 3

func unlockHostSSHKeys(values map[string]string, sshNames map[string]struct{}, prompt func(name string) (string, error)) error {
	for name := range sshNames {
		pemData, ok := values[name]
		if !ok {
			continue
		}
		unlocked, err := unlockSSHKey(pemData, prompt, name)
		if err != nil {
			return fmt.Errorf("host credential %s: %w", name, err)
		}
		values[name] = unlocked
	}
	return nil
}

func sshKeyCredentialNames(policy []byte) (map[string]struct{}, error) {
	cfg, err := parsePolicyCredentials(policy)
	if err != nil {
		return nil, err
	}
	names := map[string]struct{}{}
	for name, c := range cfg.Credentials {
		if c == nil || c.PrivateKey == nil {
			continue
		}
		if c.PrivateKey.Source == "ssh-agent" {
			continue
		}
		names[bouncercfg.ProvidedKey(name, bouncercfg.SlotPrivateKey)] = struct{}{}
	}
	return names, nil
}

func unlockSSHKey(pemData string, prompt func(name string) (string, error), name string) (string, error) {
	_, err := ssh.ParsePrivateKey([]byte(pemData + "\n"))
	if err == nil {
		return pemData, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return pemData, nil
	}
	var last error
	for attempt := 0; attempt < sshKeyPassphraseAttempts; attempt++ {
		pass, err := prompt(name)
		if err != nil {
			return "", err
		}
		raw, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(pemData+"\n"), []byte(pass))
		if err != nil {
			last = err
			continue
		}
		key, ok := raw.(crypto.PrivateKey)
		if !ok {
			return "", fmt.Errorf("unlocked ssh key is not a private key")
		}
		block, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			return "", fmt.Errorf("marshal unlocked ssh key: %w", err)
		}
		return string(pem.EncodeToMemory(block)), nil
	}
	if last != nil {
		return "", fmt.Errorf("ssh key passphrase rejected: %w", last)
	}
	return "", fmt.Errorf("ssh key passphrase rejected")
}

func readSSHKeyPassphrase(req Request, name string) (string, error) {
	fd := -1
	if f, ok := req.Stdin.(*os.File); ok {
		fd = int(f.Fd())
	}
	if fd < 0 || !term.IsTerminal(fd) {
		return "", fmt.Errorf("encrypted ssh key %s needs a passphrase (run from a terminal)", name)
	}
	_, _ = fmt.Fprintf(req.Stderr, "SSH key passphrase for %s: ", name)
	pw, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(req.Stderr)
	if err != nil {
		return "", fmt.Errorf("read ssh key passphrase: %w", err)
	}
	if len(pw) == 0 {
		return "", fmt.Errorf("empty ssh key passphrase")
	}
	return string(pw), nil
}
