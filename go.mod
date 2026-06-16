module github.com/BananaLabs-OSS/Pulp-ext-mdns

go 1.25.6

require (
	github.com/BananaLabs-OSS/Pulp v0.0.0
	github.com/grandcat/zeroconf v1.0.0
	github.com/tetratelabs/wazero v1.11.0
	github.com/vmihailenco/msgpack/v5 v5.4.1
)

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/miekg/dns v1.1.27 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550 // indirect
	golang.org/x/net v0.0.0-20200114155413-6afb5195e5aa // indirect
	golang.org/x/sys v0.42.0 // indirect
)

replace github.com/BananaLabs-OSS/Pulp => ../Pulp
