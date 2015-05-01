package saml

type AccountSettings struct {
	Certificate        string
	IDP_SSO_Target_URL string
}

type AppSettings struct {
	AssertionConsumerServiceURL string
	Issuer                      string
}

func NewAccountSettings(cert string, targetUrl string) AccountSettings {
	return AccountSettings{cert, targetUrl}
}

func NewAppSettings(assertionServiceUrl string, issuer string) AppSettings {
	return AppSettings{assertionServiceUrl, issuer}
}

func (as *AccountSettings) CertificateString() (string, error) {
	cert, err := LoadCertificate(as.Certificate)
	if err != nil {
		return "", err
	} else {
		return cert, nil
	}
}
