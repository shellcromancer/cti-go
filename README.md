# Cyber Threat Intel - Go libraries

Set a libraries to interact with CTI datasets. Lots of the functionality here exists in various python libraries but most Golang versions seem to be for older versions of the CTI "standards".

## Future Work

### Exchange Protocols

- [ ] TAXII 1.1 (Support legacy intergrations)

### Data Formats

- [ ] STIX 1.X
- [ ] STIX 2.X
- [ ] OpenIOC (?)
- [ ] CAPEC 3.X
- [ ] D3FEND 0.X (?)
- [ ] MAEC (?)
- [ ] RSS (?)

### CLI Features

- [ ] EclecticIQ/Cabby feature parity
- [ ] Warning on TLP:AMBER+ data views

### Library Features

- [x] Classify observable types
- [ ] Defang observables
- [x] Refang observables

## References

1. [TAXII 1.X](https://taxiiproject.github.io/documentation/)
2. [TAXII 2.X](https://oasis-open.github.io/cti-documentation/taxii/intro)
3. [STIX 1.X](https://stixproject.github.io)
4. [STIX 2.X](https://oasis-open.github.io/cti-documentation/stix/intro)
5. [CAPEC](https://capec.mitre.org)