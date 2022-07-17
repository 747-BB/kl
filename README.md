# klient

Klient is an http client for golang that mimics Chromes h1 and h2 requests so it can't be blocked by certain WAFs.

## Features

- [x] HTTP1 Normal Header order
- [x] HTTP2 Normal Header order
- [x] HTTP2 pseudo Header order
- [x] Custom H2 Settings
- [x] Chrome TLS Fingerprint / Custom Specs TLS Fingerprint
- [x] Latest TLS Fingerprints [Chrome 94 and IOS 14.8] (added in [kTLS](https://github.com/klient-tls/ktls#:~:text=IOS%2014.8%20%2B%20Chrome%2094%20Client%20Hello))
- [x] Certificate Compression (added in [kTLS](https://github.com/klient-tls/ktls#:~:text=Certificate%20Compression%20(Only%20decompresses%20the%20server%20certificate%20message%20(if%20compressed)%20since%20there%20was%20no%20site%20that%20requested%20a%20client%20certificate%20to%20even%20test%20the%20client%20certificate%20compression%20on.)))
- [x] Accepts all encodings [gzip, deflate, brotli]
- [x] SSL pinning (strict- & non strict mode) (added in [kTLS](https://github.com/klient-tls/ktls#:~:text=SSL%20Pinning%20(strict-%20%26%20non%20sctrict%20mode)))
- [x] Is able to handle server pushes for H2.

[Jump to Examples](https://github.com/klient-tls/klient#examples)

# Test with charles

If you would like to route your requests through Charles for testing simply start Charles and add this field to your Transport configuration.
```go
Proxy: http.ProxyURL(&url.URL{
	Scheme: "http",
	Host:   "localhost:8888",
}),
```
It's important for you to not use the Charles Reverse Proxy feature and then set the reverse proxy as an actual URL. For some sites this does not even work with Chrome and will only lead to issues.

# Documentation

## Header Order (HTTP1 and HTTP2)

To define a Header Order simply add http.HeaderOrderKey to your req.Header.

- :warning: When using a Cookie Jar the "Cookie" Header will automatically be written into your Headers which means you will only have to define it's place in the order in your Header Order.

- :warning: When defining content-length in your Header Order it will only be written to the request if you actually have a request body. The size will automatically be calculated. If you don't add it in your Header Order it won't be written to the request.

- :warning: All keys are case sensitive (meaning you can't name a key "accept" in your Headers and "Accept" in your Header Order).

- :warning: The only key that isn't case sensitive is the "Cookie" Header because the CookieJar adds it as "Cookie" but we still want to be able to send it as "cookie" which we can by adding "cookie" to our Header Order.

- :warning: If no Header Order is defined the standard Head Order will be used.

- :warning: If a Header Order is defined ONLY the keys inside of it it will be written to the connection.

## HTTP2 Pseudo Header Order

To define an HTTP2 Pseudo Header Order simply add http.PseudoHeaderOrderKey to your req.Header.

- :warning: If a key isn't in http.PseudoHeaderOrderKey it won't be written to the connection which might cause a failed connection. Be sure to always use {":method", ":authority", ":scheme", ":path"}.

## Custom HTTP2 Settings

To define custom HTTP2 Settings simply add them into &http.Transport upon creating an &http.Client.

- :warning: Defining invalid HTTP2 Settings might cause a failed connection.
- :warning: Undefined HTTP2 Settings will be written as 0 which might cause a failed connection.

## Custom TLS Fingerprint (JA3)

To define a custom TLS Fingerprint (JA3) simply add it into &http.Transport upon creating an &http.Client.

If for some reason you don't want to use the premade specs, you can define custom ones.

To get these Custom Specs simply visit https://tlsfingerprint.io/ with the Device/Browser you want to fingerprint, click the ID, scroll down to "uTLS generated code" and 
click "Click to expand".

- :warning: ClientHelloSpec will only be applied if the ClientHello is set to tls.HelloCustom.
- :warning: https://tlsfingerprint.io/ will give you code that doesn't 100% work and you will have to change some settings.
	- e.g &tls.UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}, => &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}, (just watch your IDEs warnings)
- :warning: Never use FakeCertCompressionAlgsExtension in your ClientHelloSpec. It will send a wrong message which will cause the connection to fail if the site you are targeting actually compresses certificates (e.g Cloudflare) and you can't decompress.
	- :x:
	```go
	&tls.FakeCertCompressionAlgsExtension{[]tls.CertCompressionAlgo{
		tls.CertCompressionBrotli,
	}},
	```

	- :ballot_box_with_check:
	```go
	&tls.CompressCertificateExtension{[]tls.CertCompressionAlgo{
		tls.CertCompressionBrotli,
	}},
	```
- :information_source: Currently we are only decompressing the Server Certificate but aren't compressing the Client Certificate which is allowed in RFC8879. We aren't compressing the Client Certificate because in most cases it isn't even requested in the Handshake (e.g cloudflare).

## SSL Pinning

SSL Pinning can protect your software from MITM attacks. To add SSL Pinning simply add it to your &tls.Config in &http.Transport upon creating an &http.Client.

- If RecordServerCertificates is true, the certificates provided by the server will be written to a file in the dir of the client so they can later be pinned.
- SSLPins contains all the ServerNames + their respective certificates, that you would like to pin (copy paste the ones in the files generated by your first run when RecordServerCertificates was set to true).
- SSLPinFunction will be triggered after a bad event was detected.
- If StrictSSLPinning is true it will trigger SSLPinFunction if the ServerName isn't in SSLPins. If StrictSSLPinning is false it will only trigger it when the certificates don't match.
	- :warning: If a proxy is being used, the proxy host hasn't been pinned and StrictSSLPinning is true then SSLPinFunction will be triggered.

# Examples

## Example 1 

Creating a new Client / Request with a preset ClientHello:<br>
*Code Snippet from [this example](https://github.com/klient-tls/klient/blob/master/examples/presetClientHelloSpec/presetClientHelloSpec.go)*
```go
c := &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify:       true,
			RecordServerCertificates: false,
			SSLPins: map[string][][]byte{
				"ja3er.com": Certs,
			},
			SSLPinFunction: func() {
				println("BAD PIN DETECTED")
				os.Exit(0)
			},
			StrictSSLPinning: true,
		},
		ForceAttemptHTTP2: true,
		H2Settings: http.H2Settings{
			HeaderTableSize:      65536,
			EnablePush:           1,
			MaxConcurrentStreams: 1000,
			InitialWindowSize:    6291456,
			MaxFrameSize:         16384,
			MaxHeaderListSize:    262144,
		},
		MaxIdleConnsPerHost: 1024,
		ClientHello:         tls.HelloChrome_94,
	},
	Jar: jar,
}
req, err := http.NewRequest(http.MethodGet, "https://ja3er.com/json", nil)
if err != nil {
	panic(err)
}

req.Header = http.Header{
	"accept-encoding":         {"gzip, deflate, br"},
	"user-agent":              {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"},
	"accept":                  {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
	http.HeaderOrderKey:       {"accept-encoding", "user-agent", "cookie", "accept"},
	http.PseudoHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
}
```

## Example 2

Creating a new Client / Request with a custom ClientHelloSpec:<br>
*Code Snippet from [this example](https://github.com/klient-tls/klient/blob/master/examples/customClientHelloSpec/customClientHelloSpec.go)*
```go
c := &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify:       true,
			RecordServerCertificates: false,
			SSLPins: map[string][][]byte{
				"ja3er.com": Certs,
			},
			SSLPinFunction: func() {
				println("BAD PIN DETECTED")
				os.Exit(0)
			},
			StrictSSLPinning: true,
		},
		ForceAttemptHTTP2: true,
		H2Settings: http.H2Settings{
			HeaderTableSize:      65536,
			EnablePush:           1,
			MaxConcurrentStreams: 1000,
			InitialWindowSize:    6291456,
			MaxFrameSize:         16384,
			MaxHeaderListSize:    262144,
		},
		MaxIdleConnsPerHost: 1024,
		ClientHello:         tls.HelloCustom,
		ClientHelloSpec: tls.ClientHelloSpec{
			CipherSuites: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []tls.TLSExtension{
				&tls.UtlsGREASEExtension{},
				&tls.SNIExtension{},
				&tls.UtlsExtendedMasterSecretExtension{},
				&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
				&tls.SupportedCurvesExtension{[]tls.CurveID{
					tls.CurveID(tls.GREASE_PLACEHOLDER),
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
				}},
				&tls.SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&tls.SessionTicketExtension{},
				&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&tls.StatusRequestExtension{},
				&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.PSSWithSHA256,
					tls.PKCS1WithSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.PSSWithSHA384,
					tls.PKCS1WithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA512,
				}},
				&tls.SCTExtension{},
				&tls.KeyShareExtension{[]tls.KeyShare{
					{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: tls.X25519},
				}},
				&tls.PSKKeyExchangeModesExtension{[]uint8{
					tls.PskModeDHE,
				}},
				&tls.SupportedVersionsExtension{[]uint16{
					tls.GREASE_PLACEHOLDER,
					tls.VersionTLS13,
					tls.VersionTLS12,
					tls.VersionTLS11,
					tls.VersionTLS10,
				}},
				&tls.CompressCertificateExtension{[]tls.CertCompressionAlgo{
					tls.CertCompressionBrotli,
				}},
				&tls.GenericExtension{Id: 0x4469}, // WARNING: UNKNOWN EXTENSION, USE AT YOUR OWN RISK
				&tls.UtlsGREASEExtension{},
				&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
			},
		},
	},
	Jar: jar,
}
req, err := http.NewRequest(http.MethodGet, "https://ja3er.com/json", nil)
if err != nil {
	panic(err)
}

req.Header = http.Header{
	"accept-encoding":         {"gzip, deflate, br"},
	"user-agent":              {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"},
	"accept":                  {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
	http.HeaderOrderKey:       {"accept-encoding", "user-agent", "cookie", "accept"},
	http.PseudoHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
}
```
