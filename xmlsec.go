package saml

import (
	"errors"
	"fmt"
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

	_, isSigned := exec.Command("xmlsec1", "--verify", "--pubkey-cert-pem", pubCertPath, "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response", samlXmlsecInput.Name()).Output()

	if isSigned == nil {
		return nil
	} else {
		fmt.Println(isSigned)
		return errors.New("error verifing signature.")
	}
}
