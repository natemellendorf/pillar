package main

import (
	"net"
	"time"
	"log"
	"io"
	"crypto/rand"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/curve25519"
)

func x25519Keypair() ([]byte, []byte) {
	var pubkey, privkey [32]byte
	if _, err := io.ReadFull(rand.Reader, privkey[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return pubkey[:], privkey[:]
}

func newCaCert(name string, before, after time.Time, ips, subnets []*net.IPNet, groups []string) (*cert.NebulaCertificate, []byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           name,
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           true,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	if len(ips) > 0 {
		nc.Details.Ips = ips
	}

	if len(subnets) > 0 {
		nc.Details.Subnets = subnets
	}

	if len(groups) > 0 {
		nc.Details.Groups = groups
	}

	err = nc.Sign(priv)
	if err != nil {
		return nil, nil, nil, err
	}
	return nc, pub, priv, nil
}

func newCert(name string, ca *cert.NebulaCertificate, key []byte, before, after time.Time, ips, subnets []*net.IPNet, groups []string) (*cert.NebulaCertificate, []byte, []byte, error) {
	issuer, err := ca.Sha256Sum()
	if err != nil {
		return nil, nil, nil, err
	}

	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	if len(groups) == 0 {
		groups = []string{"group1", "group2", "group3"}
	}

	if len(ips) == 0 {
		ips = []*net.IPNet{
			{IP: net.ParseIP("10.10.10.1").To4(), Mask: net.IPMask(net.ParseIP("255.255.255.0").To4())},
		}
	}

	if len(subnets) == 0 {
		subnets = []*net.IPNet{
			{IP: net.ParseIP("10.10.10.0").To4(), Mask: net.IPMask(net.ParseIP("255.255.255.0").To4())},
		}
	}

	pub, rawPriv := x25519Keypair()

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           name,
			Ips:            ips,
			Subnets:        subnets,
			Groups:         groups,
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           false,
			Issuer:         issuer,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	err = nc.Sign(key)
	if err != nil {
		return nil, nil, nil, err
	}

	return nc, pub, rawPriv, nil
}

func main() {

	// Create CA certificate // 365 Days
	ca, _, caKey, err := newCaCert("caCert1", time.Now(), time.Now().Add(8760*time.Hour), []*net.IPNet{}, []*net.IPNet{}, []string{})
	if err != nil {
		log.Fatalln(err)
	}

	// Convert CA certificate to PEM
	caPem, err := ca.MarshalToPEM()

	log.Println("CA PRIVATE KEY:")
	log.Println("\n",string(cert.MarshalEd25519PrivateKey(caKey)))
	log.Println("---------------")
	log.Println("CA PUBLIC KEY:")
	log.Println("\n",string(caPem))
	

	// Create new CA Pool
	caPool := cert.NewCAPool()
	caPool.AddCACertificate(caPem)

	// Create and sign a new certificate // 30 Days
	c, _, cKey, err := newCert("cert1", ca, caKey, time.Now(), time.Now().Add(720*time.Hour), []*net.IPNet{}, []*net.IPNet{}, []string{})
	if err != nil {
		log.Fatalln(err)
	}

	// Verify certificate
	v, err := c.Verify(time.Now(), caPool)
	if err != nil || !v {
		log.Fatalln(err)
	}

	// Convert new certificate to PEM
	cPem, err := c.MarshalToPEM()

	// Log certs
	log.Println("Cert PRIVATE KEY:")
	log.Println("\n",string(cert.MarshalEd25519PrivateKey(cKey)))
	log.Println("---------------")
	log.Println("Cert PUBLIC KEY:")
	log.Println("\n",string(cPem))
	

}
