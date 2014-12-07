package saml

import (
	"encoding/xml"
)

type Response struct {
	XMLName      xml.Name
	SAMLP        string `xml:"saml2p,attr"`
	Destination  string `xml:"Destination,attr"`
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`

	Assertion Assertion `xml:"Assertion"`
	Signature Signature `xml:"Signature"`
	Issuer    Issuer    `xml:"Issuer"`
	Status    Status    `xml:"Status"`
}

type Assertion struct {
	XMLName            xml.Name
	ID                 string `xml:"ID,attr"`
	Version            string `xml:"Version,attr"`
	SAML               string `xml:"saml2,attr"`
	IssueInstant       string `xml:"IssueInstant,attr"`
	Subject            Subject
	Conditions         Conditions
	AttributeStatement AttributeStatement
}

type Conditions struct {
	XMLName      xml.Name
	NotBefore    string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
}

type Subject struct {
	XMLName             xml.Name
	SubjectConfirmation SubjectConfirmation
}

type SubjectConfirmation struct {
	XMLName                 xml.Name
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

type Status struct {
	XMLName    xml.Name
	StatusCode StatusCode `xml:"StatusCode"`
}

type SubjectConfirmationData struct {
	Address      string `xml:",attr"`
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

type StatusCode struct {
	Value string `xml:"Value"`
}

type AttributeStatement struct {
	Attributes []Attribute
}

type Attribute struct {
	XMLName        xml.Name
	Name           string `xml:",attr"`
	FriendlyName   string `xml:",attr"`
	NameFormat     string `xml:",attr"`
	AttributeValue AttributeValue
}

type AttributeValue struct {
	XMLName xml.Name
	Value   string `xml:"Value"`
}
