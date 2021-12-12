// Package observable contains utilities for classifying and propper hanlding of various
// obersable types for CTI work.
package observable

type Type string

const (
	MD5Hash          = Type("md5")
	SHA1Hash         = Type("sha1")
	SHA256Hash       = Type("sha256")
	IP               = Type("ip")
	Domain           = Type("domain")
	URL              = Type("url")
	Email            = Type("email")
	AutonomousSystem = Type("as")
	MAC              = Type("mac")
	Certificate      = Type("certificate")
)

// Traffic Light Protocol (TLP) definitions
// https://www.cisa.gov/tlp
const (
	// Sources may use TLP:WHITE when information carries minimal or no
	// foreseeable risk of misuse, in accordance with applicable rules and
	// procedures for public release.
	//
	// Subject to standard copyright rules, TLP:WHITE information may be
	// distributed without restriction.
	TLPWhite = "TLP:WHITE"

	// Sources may use TLP:GREEN when information is useful for the awareness of
	// all participating organizations as well as with peers within the broader
	// community or sector.
	//
	// Recipients may share TLP:GREEN information with peers and partner organizations
	// within their sector or community, but not via publicly accessible channels.
	// Information in this category can be circulated widely within a particular
	// community. TLP:GREEN information may not be released outside of the community.
	TLPGreen = "TLP:GREEN"
	// Sources may use TLP:AMBER when information requires support to be effectively
	// acted upon, yet carries risks to privacy, reputation, or operations if shared
	// outside of the organizations involved.
	//
	// Recipients may only share TLP:AMBER information with members of their own
	// organization, and with clients or customers who need to know the information
	// to protect themselves or prevent further harm. Sources are at liberty to
	// specify additional intended limits of the sharing: these must be adhered to.
	TLPAmber = "TLP:AMBER"

	// Sources may use TLP:RED when information cannot be effectively acted upon
	// by additional parties, and could lead to impacts on a party's privacy,
	// reputation, or operations if misused.
	TLPRed = "TLP:RED"
)
