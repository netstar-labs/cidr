module github.com/netstar-labs/cidr/cmd/mmdb-write

go 1.25.0

require (
	github.com/maxmind/mmdbwriter v1.2.0
	github.com/netstar-labs/cidr v0.0.0
	github.com/oschwald/maxminddb-golang/v2 v2.4.1
)

require (
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/netstar-labs/cidr => ../../
