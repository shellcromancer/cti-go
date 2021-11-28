package stix

import "time"

// Relationship links together two SDOs or SCOs in order to describe how they are
// related to each other. If SDOs and SCOs are considered "nodes" or "vertices" in
// the graph, the Relationship Objects (SROs) represent "edges".
type Relationship struct {
	CommonRequired

	RelationshipType string    `json:"relationship_type,omitempty"`
	Description      string    `json:"description,omitempty"`
	SourceRef        string    `json:"source_ref,omitempty"`
	TargetRef        string    `json:"target_ref,omitempty"`
	StartTime        time.Time `json:"start_time,omitempty"`
	StopTime         time.Time `json:"stop_time,omitempty"`
}

// Relationship links together two SDOs or SCOs in order to describe how they are
// related to each other. If SDOs and SCOs are considered "nodes" or "vertices" in
// the graph, the Relationship Objects (SROs) represent "edges".
type Sighting struct {
	CommonRequired

	Description string
	FirstSeen   time.Time
	LastSeen    time.Time
	Count       int

	// An ID reference to the SDO that was sighted (e.g., Indicator or Malware).
	SightingOfRef string
	// A list of ID references to the Observed Data objects that contain the raw
	// cyber data for this Sighting.
	ObservedDataRefs []string

	// A list of ID references to the Identity or Location objects describing the
	// entities or types of entities that saw the sighting.
	WhereSitedRefs []string

	// Summary data is an aggregation of previous Sightings reports and should
	// not be considered primary source data.
	Summary bool
}
