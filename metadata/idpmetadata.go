package metadata

import (
	"encoding/xml"
	"fmt"

	"github.com/RobotsAndPencils/gosaml"
)

func NewMetadata(appSettings *saml.AppSettings, accountSettings *saml.AccountSettings) *Metadata {

	return &Metadata{AccountSettings: accountSettings, AppSettings: appSettings}
}

func (m Metadata) Get() (string, error) {
	cert, err := m.AccountSettings.CertificateString()
	if err != nil {
		return "", err
	}

	d := EntityDescriptor{
		XMLName: xml.Name{
			Local: "md:EntityDescriptor",
		},
		DS:       "http://www.w3.org/2000/09/xmldsig#",
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		MD:       "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityId: m.AppSettings.AssertionConsumerServiceURL,

		Extensions: Extensions{
			XMLName: xml.Name{
				Local: "md:Extensions",
			},
			Alg:    "urn:oasis:names:tc:SAML:metadata:algsupport",
			MDAttr: "urn:oasis:names:tc:SAML:metadata:attribute",
			MDRPI:  "urn:oasis:names:tc:SAML:metadata:rpi",

			// EntityAttributes: EntityAttributes{
			// 	XMLName: xml.Name{
			// 		Local: "mdattr:EntityAttributes",
			// 	},

			// 	SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
			// 	EntityAttributes: []EntityAttribute{
			// 		EntityAttribute{
			// 			XMLName: xml.Name{
			// 				Local: "saml:Attribute",
			// 			},
			// 			Name:           "https://idm.utsystem.edu/entity-category",
			// 			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			// 			AttributeValue: "---TODO---",
			// 		},
			// 	},
			// },
		},
		SPSSODescriptor: SPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			SigningKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "signing",
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Value: cert,
						},
					},
				},
			},
			EncryptionKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "encryption",
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Value: cert,
						},
					},
				},
			},
			// SingleLogoutService{
			// 	XMLName: xml.Name{
			// 		Local: "md:SingleLogoutService",
			// 	},
			// 	Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			// 	Location: "---TODO---",
			// },
			AssertionConsumerServices: []AssertionConsumerService{
				AssertionConsumerService{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: m.AppSettings.AssertionConsumerServiceURL,
					Index:    "0",
				},
				AssertionConsumerService{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
					Location: m.AppSettings.AssertionConsumerServiceURL,
					Index:    "1",
				},
			},
		},
	}
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	newMetadata := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b)
	return string(newMetadata), nil
}
