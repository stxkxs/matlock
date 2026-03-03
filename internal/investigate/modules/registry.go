package modules

import "github.com/stxkxs/matlock/internal/investigate"

// All returns every registered probe module in recommended execution order.
func All() []investigate.Module {
	return []investigate.Module{
		NewDNSModule(),
		NewSSLModule(),
		NewHTTPModule(),
		NewPortsModule(),
		&WhoisModule{},
		&SubdomainModule{},
		&CrtModule{},
		&CORSModule{},
		&WAFModule{},
		&TechModule{},
		&DNSSECModule{},
		&Files{},
		&ShodanModule{},
		&VirusTotalModule{},
		&SecTrailsModule{},
		&WaybackModule{},
		&AXFRModule{},
		&Methods{},
		&Dirs{},
		&JSAnalysis{},
		&Favicon{},
		&ReverseIPModule{},
		&ASNModule{},
		&IP{},
		&EmailSec{},
		&Takeover{},
	}
}
