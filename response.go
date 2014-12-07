package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"

	"time"
)

/*
type Response struct {
	XmlDoc      string
	Settings    AccountSettings
	certificate x509.Certificate
}
*/

func Parse(resp string, appSettings *AppSettings, accountSettings *AccountSettings) (Response, error) {
	x := Response{}
	decode, err := base64.StdEncoding.DecodeString(resp)
	if err != nil {
		fmt.Println(err)
	}

	err = xml.Unmarshal(decode, &x)
	if err != nil {
		return Response{}, err
	}

	err = VerifySignature(string(decode), "cert.crt")
	if err != nil {
		return Response{}, err
	}

	err = IsValid(&x, appSettings, accountSettings)
	fmt.Println(x)
	return x, err

}

func IsValid(x *Response, appSettings *AppSettings, accountSettings *AccountSettings) error {
	if x.Version != "2.0" {
		return errors.New("unsupported SAML Version.")
	}

	if len(x.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response.")
	}

	if len(x.Assertion.ID) == 0 {
		return errors.New("no Assertions.")
	}

	if len(x.Signature.SignatureValue.Value) == 0 {
		return errors.New("no signature.")
	}

	if x.Destination != appSettings.AssertionConsumerServiceURL {
		return errors.New("destination mismath expected: " + appSettings.AssertionConsumerServiceURL + " not " + x.Destination)
	}

	if x.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("asserition method exception")
	}

	if x.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != appSettings.AssertionConsumerServiceURL {
		return errors.New("subject recipient miss match, expected: " + appSettings.AssertionConsumerServiceURL + " not " + x.Destination)
	}

	//CHECK TIMES
	expires := x.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	notOnOrAfter, e := time.Parse(time.RFC3339, expires)
	if e != nil {
		return e
	}
	if notOnOrAfter.Before(time.Now()) {
		return errors.New("assertion has expired on: " + expires)
	}

	return nil
}
