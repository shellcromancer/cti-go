// Package taxii provides the formats and a client for working with the Trusted
// Automated Exchange of Intelligence Information (TAXII) protocol. TAXII is commonly
// used to exchange cyber threat intelligence (CTI) over HTTPS with specific URL paths.
// Exchanged data is repesented in as Structured Threat Information Expression (STIX).
package taxii

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/shellcromancer/cti-go/pkg/stix"
)

// Version of the TAXII protocol to follow. Defaults to 2.0 with support for more.
const (
	Version1_1 = "1.1"
	Version2_0 = "2.0"
	Version2_1 = "2.1"
)

const (
	defaultLogLevel = zerolog.InfoLevel
)

var (
	ErrInvalidServer      = errors.New("invalid TAXII server")
	ErrUnsupportedVersion = errors.New("unsupported TAXII version")
)

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out: os.Stdout,
	})
	taxiiLogLevel, ok := os.LookupEnv("TAXII_LOG")
	if ok {
		l, err := zerolog.ParseLevel(taxiiLogLevel)
		if err != nil {
			zerolog.SetGlobalLevel(defaultLogLevel)
		}
		zerolog.SetGlobalLevel(l)
	} else {
		zerolog.SetGlobalLevel(defaultLogLevel)
	}
}

type Client struct {
	Server string

	httpClient *http.Client
	version    string
	username   string
	password   string
}

func NewClient(opts ...ClientOption) (*Client, error) {
	c := &Client{
		version: Version2_0,
	}

	for _, opt := range opts {
		opt(c)
	}

	err := validateClient(c)
	if err != nil {
		return c, err
	}

	c.httpClient = &http.Client{
		Transport: taxiiTransport{
			r:       http.DefaultTransport,
			version: c.version,
			user:    c.username,
			pass:    c.password,
		},
	}

	return c, nil
}

type ClientOption func(*Client)

func WithServer(s string) ClientOption {
	return func(c *Client) {
		c.Server = s
	}
}

func WithVersion(v string) ClientOption {
	return func(c *Client) {
		c.version = v
	}
}

func WithBasicAuth(user, pass string) ClientOption {
	return func(c *Client) {
		c.username = user
		c.password = pass
	}
}

func validateClient(c *Client) error {
	if c.Server == "" {
		return fmt.Errorf("%w: no server was provided. Add one using WithServer(\"{ServerURL}\")",
			ErrInvalidServer)
	}

	if !strings.HasPrefix(c.Server, "http") {
		return fmt.Errorf("%w: server must be a HTTP resource. got=(%s)", ErrInvalidServer,
			c.Server)
	}

	if c.version != Version1_1 && c.version != Version2_0 &&
		c.version != Version2_1 {
		return fmt.Errorf("%w: got=(%s) want=(1.1, 2.X)", ErrUnsupportedVersion, c.version)
	}

	return nil
}

type taxiiTransport struct {
	r       http.RoundTripper
	version string
	user    string
	pass    string
}

func (tt taxiiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", `taxiicab-client/0.0.0`)

	if tt.user != "" {
		req.SetBasicAuth(tt.user, tt.pass)
	}

	// set default encoding as the value for 2.x
	encoding := "json"

	// Set "Accept" header based on path + versions
	if tt.version == Version1_1 {
		encoding = "xml"
		req.Header.Add("Accept", `application/xml`)
		req.Header.Add("Content-Type", "application/xml")
	} else if tt.version == Version2_0 {
		req.Header.Add("Accept", fmt.Sprintf("application/vnd.oasis.taxii+json; version=%s", tt.version))

		if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/objects/") {
			req.Header.Set("Accept", `application/vnd.oasis.stix+json; version=2.0`)
		}
	} else if tt.version == Version2_1 {
		req.Header.Add("Accept", fmt.Sprintf("application/taxii+json;version=%s", tt.version))
	}

	req.Header.Add("X-Taxii-Accept", fmt.Sprintf("urn:taxii.mitre.org:message:%s:1.1", encoding))
	req.Header.Add("X-Taxii-Content-Type", fmt.Sprintf("urn:taxii.mitre.org:message:%s:1.1", encoding))
	req.Header.Add("X-Taxii-Protocol", `urn:taxii.mitre.org:protocol:http:1.0`)
	req.Header.Add("X-Taxii-Services", `urn:taxii.mitre.org:services:1.1`)

	return tt.r.RoundTrip(req)
}

type DiscoveryResp struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Contact     string   `json:"contact"`
	Default     string   `json:"default"`
	APIRoots    []string `json:"api_roots"`
}

// discoveryResponse for TAXII 1.1
type discoveryResponseV1 struct {
	XMLName         xml.Name `xml:"Discovery_Response"`
	Text            string   `xml:",chardata"`
	Taxii           string   `xml:"taxii,attr"`
	Taxii11         string   `xml:"taxii_11,attr"`
	Tdq             string   `xml:"tdq,attr"`
	MessageID       string   `xml:"message_id,attr"`
	InResponseTo    string   `xml:"in_response_to,attr"`
	ServiceInstance []struct {
		Text string `xml:",chardata"`
		// Type is one of: DISCOVERY, POLL, COLLECTION_MANAGEMENT
		Type            string `xml:"service_type,attr"`
		Version         string `xml:"service_version,attr"`
		Available       string `xml:"available,attr"`
		ProtocolBinding string `xml:"Protocol_Binding"`
		Address         string `xml:"Address"`
		MessageBinding  string `xml:"Message_Binding"`
		Message         string `xml:"Message"`
	} `xml:"Service_Instance"`
}

type taxiiMessageV1 struct {
	XMLName      xml.Name `xml:"Status_Message"`
	Text         string   `xml:",chardata"`
	Taxii        string   `xml:"taxii,attr"`
	Taxii11      string   `xml:"taxii_11,attr"`
	Tdq          string   `xml:"tdq,attr"`
	MessageID    string   `xml:"message_id,attr"`
	InResponseTo string   `xml:"in_response_to,attr"`
	StatusType   string   `xml:"status_type,attr"`
	Message      string   `xml:"Message"`
}

func (c *Client) Discovery() (d DiscoveryResp, err error) {
	var path string
	switch c.version {
	case Version1_1, Version2_0:
		path = fmt.Sprintf("%s/taxii/", c.Server)
	case Version2_1:
		path = fmt.Sprintf("%s/taxii2/", c.Server)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
	if err != nil {
		return DiscoveryResp{}, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return DiscoveryResp{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		out, _ := httputil.DumpRequestOut(req, true)
		fmt.Println(string(out))
		out, _ = httputil.DumpResponse(resp, true)
		fmt.Println(string(out))

		return DiscoveryResp{}, fmt.Errorf("error from server response: status=(%s) status-code=(%d) content-length=(%d)",
			resp.Status, resp.StatusCode, resp.ContentLength)
	}

	switch c.version {
	case Version1_1:
		var d1 discoveryResponseV1
		err = xml.NewDecoder(resp.Body).Decode(&d1)
		if err != nil {
			return DiscoveryResp{}, err
		}

		for _, instance := range d1.ServiceInstance {
			if instance.Type == "COLLECTION_MANAGEMENT" {
				d.APIRoots = append(d.APIRoots, instance.Address)
				log.Info().Msgf("Got a collection management instance: %s", instance.Text)
			}
		}
	case Version2_0, Version2_1:
		err = json.NewDecoder(resp.Body).Decode(&d)
		if err != nil {
			return DiscoveryResp{}, err
		}
	}

	return d, nil
}

type APIRoot struct {
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	MaxContentLength string   `json:"max_content_length"`
	Versions         []string `json:"versions"`
}

func (c *Client) GetAPIRoot(rootURL string) (r *APIRoot, err error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rootURL, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

type Collection struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CanRead     bool     `json:"can_read"`
	CanWrite    bool     `json:"can_write"`
	MediaTypes  []string `json:"media_types"`
}

// nolint: deadcode, unused
type collectionResponseV1 struct {
	taxiiMessageV1

	XMLName    xml.Name `xml:"Collection_Information_Response"`
	Text       string   `xml:",chardata"`
	Collection struct {
		Text           string `xml:",chardata"`
		CollectionName string `xml:"collection_name,attr"`
		CollectionType string `xml:"collection_type,attr"`
		Available      string `xml:"available,attr"`
		Description    string `xml:"Description"`
		PollingService []struct {
			Text            string `xml:",chardata"`
			ProtocolBinding string `xml:"Protocol_Binding"`
			Address         string `xml:"Address"`
			MessageBinding  string `xml:"Message_Binding"`
		} `xml:"Polling_Service"`
		SubscriptionService []struct {
			Text            string `xml:",chardata"`
			ProtocolBinding string `xml:"Protocol_Binding"`
			Address         string `xml:"Address"`
			MessageBinding  string `xml:"Message_Binding"`
		} `xml:"Subscription_Service"`
		ReceivingInboxService []struct {
			Text            string `xml:",chardata"`
			ProtocolBinding string `xml:"Protocol_Binding"`
			Address         string `xml:"Address"`
			MessageBinding  string `xml:"Message_Binding"`
		} `xml:"Receiving_Inbox_Service"`
	} `xml:"Collection"`
}

func (c *Client) ListCollections(rootURL string) (collections []Collection, err error) {
	ctx := context.Background()
	var req *http.Request

	switch c.version {
	case Version1_1:
		// POST $HOST/taxii/collections
		//
		// <taxii_11:Collection_Information_Request xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1"message_id="26300"/>
		url := fmt.Sprintf("%s/collections/", strings.TrimSuffix(rootURL, "/collections"))
		body := strings.NewReader(fmt.Sprintf(`<taxii_11:Collection_Information_Request xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1"message_id="%d"/>`, 26300))

		req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, body)
		if err != nil {
			return nil, fmt.Errorf("taxii: failed building collections 1.1 request: %w", err)
		}
	case Version2_0, Version2_1:
		// GET $HOST/taxii/collections/
		url := fmt.Sprintf("%s/collections/", strings.Trim(rootURL, "/"))
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("taxii: failed building collections 2.x request: %w", err)
		}
	}
	log.Info().Msgf("making a TAXII %s collection request to %s. method=(%s)", c.version, req.URL.String(), req.Method)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		out, _ := httputil.DumpRequestOut(req, true)
		fmt.Println(string(out))
		out, _ = httputil.DumpResponse(resp, true)
		fmt.Println(string(out))

		return nil, fmt.Errorf("taxii: error from fetching collections: status=(%s) status-code=(%d) content-length=(%d)",
			resp.Status, resp.StatusCode, resp.ContentLength)
	}

	var collectionsResp struct {
		Collections []Collection `json:"collections"`
	}

	switch c.version {
	case Version1_1:
		var respMessage taxiiMessageV1
		err = xml.NewDecoder(resp.Body).Decode(&respMessage)
		if err != nil {
			return nil, err
		}
		if respMessage.StatusType == "BAD_MESSAGE" {
			return nil, fmt.Errorf("taxii: error from fetching collections: status=(%s) message=(%s)",
				respMessage.StatusType, respMessage.Message)
		}
	case Version2_0, Version2_1:
		err = json.NewDecoder(resp.Body).Decode(&collectionsResp)
		if err != nil {
			return nil, err
		}
	}

	return collectionsResp.Collections, nil
}

func (c *Client) GetObjects(rootURL, collectionID string) (b stix.Bundle, err error) {
	path := fmt.Sprintf("%s/collections/%s/objects/", strings.Trim(rootURL, "/"), collectionID)
	ctx := context.Background()

	var req *http.Request
	switch c.version {
	case Version1_1:
		payload := fmt.Sprintf(`<taxii_11:Poll_Request xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" collection_name="%s">
			<taxii_11:Poll_Parameters allow_asynch="false">
				<taxii_11:Response_Type>FULL</taxii_11:Response_Type>
			</taxii_11:Poll_Parameters>
		</taxii_11:Poll_Request>`, collectionID)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, path, strings.NewReader(payload))
		if err != nil {
			return stix.Bundle{}, err
		}
	case Version2_0, Version2_1:
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, path, http.NoBody)
		if err != nil {
			return stix.Bundle{}, err
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return stix.Bundle{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		out, _ := httputil.DumpRequestOut(req, true)
		fmt.Println(string(out))
		out, _ = httputil.DumpResponse(resp, true)
		fmt.Println(string(out))

		return stix.Bundle{}, fmt.Errorf("error from server response: status=(%s) status-code=(%d) content-length=(%d)",
			resp.Status, resp.StatusCode, resp.ContentLength)
	}

	err = json.NewDecoder(resp.Body).Decode(&b)
	if err != nil {
		return stix.Bundle{}, err
	}

	return b, nil
}
