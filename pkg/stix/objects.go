package stix

import (
	"encoding/json"
	"time"
)

type CommonRequired struct {
	Type              string    `json:"type"`
	SpecVersion       string    `json:"spec_version,omitempty"`
	ID                string    `json:"id"`
	Created           time.Time `json:"created"`
	Modified          time.Time `json:"modified"`
	CreatedByRef      string    `json:"created_by_ref"`
	ObjectMarkingRefs []string  `json:"object_marking_refs"`
	Revoked           bool      `json:"revoked,omitempty"`
	Labels            []string  `json:"labels,omitempty"`
	Confidence        int       `json:"confidence,omitempty"`
	Lang              string    `json:"lang,omitempty"`
	Defanged          bool      `json:"defanged,omitempty"`
}

// External references are used to describe pointers to information represented
// outside of STIX. For example, a Malware object could use an external reference
// to indicate an ID for that malware in an external database or a report could
// use references to represent source material.
type ExternalReference struct {
	// SourceName is the source that the external-reference is defined within.
	SourceName  string            `json:"source_name"`
	Description string            `json:"description,omitempty"`
	ExternalID  string            `json:"external_id,omitempty"`
	URL         string            `json:"url"`
	Hashes      map[string]string `json:"hashes"`
}

// The KillChainPhase represents a phase in a kill chain, which describes the various
// phases an attacker may undertake in order to achieve their objectives.
type KillChainPhase struct {
	// KillChainName specifies which kill-chain model which will be used.
	//
	// Ex: lockheed-martin-cyber, or mitre-attack
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// AttackPattern (STIX Domain Object, SDO) is a type of TTP that describe ways that adversaries attempt to
// compromise targets. Attack Patterns are used to help categorize attacks, generalize
// specific attacks to the patterns that they follow, and provide detailed information
// about how attacks are performed. An example of an attack pattern is "spear phishing": a
// common type of attack where an attacker sends a carefully crafted e-mail message to
// a party with the intent of getting them to click a link or open an attachment to deliver
// malware. Attack Patterns can also be more specific; spear phishing as practiced by
// a particular threat actor (e.g., they might generally say that the target won a contest)
// can also be an Attack Pattern.
type AttackPattern struct {
	CommonRequired
	MITREExtension

	Name               string              `json:"name" validator:"required"`
	Description        string              `json:"description"`
	Aliases            []string            `json:"aliases"`
	ExternalReferences []ExternalReference `json:"external_references"`
	KillChainPhases    []KillChainPhase    `json:"kill_chain_phases"`
}

type MarkingDefinition struct {
	Name           string `json:"name,omitempty"`
	DefinitionType string `json:"definition_type"`
	Definition     struct {
		TLP       string `json:"tlp,omitempty"`
		Statement string `json:"statement,omitempty"`
	} `json:"definition"`
}

// Campaign is a grouping of adversarial behaviors that describes a set of malicious
// activities or attacks (sometimes called waves) that occur over a period of time
// against a specific set of targets.
//
// TODO: add struct members
type Campaign struct {
}

// Course of Action (STIX Domain Object, SDO) is an action taken either to prevent
// an attack or to respond to an attack that is in progress. It may describe technical,
// automatable responses (applying patches, reconfiguring firewalls) but can also
// describe higher level actions like employee training or policy changes. For example,
// a course of action to mitigate a vulnerability could describe applying the patch
// that fixes it.
type CourseOfAction struct {
	CommonRequired

	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Action      json.RawMessage `json:"action,omitempty"`
}

// Grouping
//
// TODO: add struct members
type Grouping struct {
}

// Identity (STIX Domain Object, SDO) represents actual individuals, organizations,
// or groups (e.g., ACME, Inc.) as well asclasses of individuals, organizations,
// systems or groups (e.g., the finance sector).
//
// The Identity SDO can capture basic identifying information, contact information,
// and the sectors that the Identity belongs to. Identity is used in STIX to represent,
// among other things, targets of attacks, information sources, object creators, and
// threat actor identities.
type Identity struct {
	CommonRequired

	Name               string   `json:"name"`
	Description        string   `json:"description,omitempty"`
	Roles              []string `json:"roles,omitempty"`
	IdentityClass      string   `json:"identity_class,omitempty"`
	Sectors            []string `json:"sectors,omitempty"`
	ContactInformation string   `json:"contact_information,omitempty"`
}

// Indicator contains a pattern that can be used to detect suspicious or malicious
// cyber activity.
//
// TODO: add struct members
type Indicator struct {
}

// Infrastructure
//
// TODO: add struct members
type Infrastructure struct {
}

// IntrusionSet (STIX Domain Object, SDO) is a grouped set of adversarial behaviors
// and resources with common properties that is believed to be orchestrated by a
// single organization. An Intrusion Set may capture multiple Campaigns or other
// activities that are all tied together by shared attributes indicating a commonly
// known or unknown Threat Actor. New activity can be attributed to an Intrusion Set
// even if the Threat Actors behind the attack are not known. Threat Actors can move
// from supporting one Intrusion Set to supporting another, or they may support multiple
// Intrusion Sets.
type InstrusionSet struct {
	CommonRequired
	MITREExtension

	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Location represents a geographic location.
//
// TODO: add struct members
type Location struct {
}

// Malware is a type of TTP that represents malicious code.
//
// TODO: update for stix 2.1
type Malware struct {
	CommonRequired
	MITREExtension

	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// MalwareAnalyis contains metadata and results of a particular static or dynamic
// analysis performed on a malware instance or family.
//
// TODO: add struct members
type MalwareAnalysis struct {
}

// Note conveys informative text to provide further context and/or to
// provide additional analysis not contained in the STIX Objects, MarkingDefinition
// objects, or Language Content objects which the Note relates to.
//
// TODO: add struct members
type Note struct {
}

// ObservedData conveys information about cyber security related entities such as
// files, systems, and networks using the STIX Cyber-observable Objects (SCOs).
//
// TODO: add struct members
type ObservedData struct {
}

// Opinion An assessment of the correctness of the information in a STIX Object
// produced by a different entity.
//
// TODO: add struct members
type Opinion struct {
}

// Report is a collection of threat intelligence focused on one or more topics,
// such as a description of a threat actor, malware, or attack technique, including
// context and related details.
//
// TODO: add struct members
type Report struct {
}

// TheatActor represents individuals, groups, or organizations believed to be
// operating with malicious intent.
//
// TODO: add struct members
type ThreatActor struct {
}

// Tool is legitimate software that can be used by threat actors to perform attacks.
type Tool struct {
	CommonRequired
	MITREExtension

	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Vulnerability is a mistake in software that can be directly used by a hacker to
// gain access to a system or network.
//
// TODO: add struct
type Vulnerability struct {
}

// Extensions not defined in STIX 2.1
type MITREExtension struct {
	// Name Type `json:",omitempty"`
	Detection            string   `json:"x_mitre_detection,omitempty"`
	Platforms            []string `json:"x_mitre_platforms,omitempty"`
	DataSources          []string `json:"x_mitre_data_sources,omitempty"`
	IsSubtechnique       bool     `json:"x_mitre_is_subtechnique,omitempty"`
	SystemRequirements   []string `json:"x_mitre_system_requirements,omitempty"`
	TacticType           []string `json:"x_mitre_tactic_type,omitempty"`
	PermissionsRequired  []string `json:"x_mitre_permissions_required,omitempty"`
	EffectivePermissions []string `json:"x_mitre_effective_permissions,omitempty"`
	DefenseBypassed      []string `json:"x_mitre_defense_bypassed,omitempty"`
	RemoteSupport        bool     `json:"x_mitre_remote_support,omitempty"`
	ImpactType           []string `json:"x_mitre_impact_type,omitempty"`
	Contributors         []string `json:"x_mitre_contributors,omitempty"`
	Version              string   `json:"x_mitre_version,omitempty"`
	Deprecated           bool     `json:"x_mitre_deprecated,omitempty"`
}

type CAPECExtension struct {
	Version            string            `json:"x_capec_version,omitempty"`
	Severity           string            `json:"x_capec_typical_severity,omitempty"`
	Status             string            `json:"x_capec_status,omitempty"`
	Abstraction        string            `json:"x_capec_abstraction,omitempty"`
	Consequences       []interface{}     `json:"x_capec_consequences,omitempty"`
	ExampleInstances   []string          `json:"x_capec_example_instances,omitempty"`
	ExecutionFlow      string            `json:"x_capec_execution_flow,omitempty"`
	LikelihoodOfAttack string            `json:"x_capec_likelihood_of_attack,omitempty"`
	ChildOfRefs        []string          `json:"x_capec_child_of_refs,omitempty"`
	Prerqeuisites      []string          `json:"x_capec_prerequisites,omitempty"`
	RequiredSkills     map[string]string `json:"x_capec_skills_required,omitempty"`
	RequiredResources  map[string]string `json:"x_capec_resources_required,omitempty"`
}

// MITRETactic extends the standard SDO.
//
// type: x-mitre-tactic
type MITRETactic struct {
	CommonRequired
	MITREExtension

	Name               string              `json:"name"`
	Description        string              `json:"description,omitempty"`
	MITREShortname     string              `json:"x_mitre_shortname"`
	ExternalReferences []ExternalReference `json:"external_references"`
}

// MITREDataSource extends the standard SDO. Can relate to many data components
// which in turn detect techniques.
//
// type: x-mitre-tactic
type MITREDataSource struct {
	CommonRequired
	MITREExtension

	Platforms        []string `json:"x_mitre_platforms,omitempty"`
	CollectionLayers []string `json:"x_mitre_collection_layers,omitempty"`
}

// MITREDataComponent extends the standard SDO and will always map back to only
// one MITRE Data Source and can have any number of techniques via detections.
//
// type: x-mitre-tactic
type MITREDataComponent struct {
	CommonRequired
	MITREExtension

	DataSourceRef string `json:"x_mitre_data_source_ref"`
}

// MITREMatrix SDO
//
// TODO: add struct members
type MITREMatrix struct {
}
