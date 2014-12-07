package saml

import (
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
)

func VerifySignature(xml string, pubCertPath string) error {
	//Write saml to
	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return err
	}

	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()

	_, isSigned := exec.Command("e:\\xmlsec\\xmlsec.exe", "--verify", "--pubkey-cert-pem", pubCertPath, "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response", samlXmlsecInput.Name()).Output()

	if isSigned == nil {
		return nil
	} else {
		return errors.New("error verifing signature.")
	}
}
