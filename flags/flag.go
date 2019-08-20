package flag

import (
	"gopkg.in/alecthomas/kingpin.v2"
	stats_flags "github.com/tkuchiki/alp/flags"
)

type Flags struct {
	Common  *Common
	Profile *Profile
	Stats   *stats_flags.GlobalFlags
}

type Common struct {
	Snaplen int
	Iface   string
	Port    int
	Pcap    string
	Lazy    bool
}

type Profile struct {
	IsProfiling bool
	IsLogging   bool
}

func NewFlags() *Flags {
	return &Flags{
		Common:  &Common{},
		Profile: &Profile{},
		Stats:   stats_flags.NewGlobalFlags(),
	}
}

func (f *Flags) InitCommonFlags(app *kingpin.Application) {
	app.Flag("snaplen", "Snap length (number of bytes max to read per packet").Default("65536").IntVar(&f.Common.Snaplen)
	app.Flag("iface", "Interface to read packets from").Default("lo0").StringVar(&f.Common.Iface)
	app.Flag("port", "Port").Required().IntVar(&f.Common.Port)
	app.Flag("pcap", "Pcap file").StringVar(&f.Common.Pcap)
	app.Flag("lazy", "If true, do lazy decoding").BoolVar(&f.Common.Lazy)
}

func (f *Flags) InitProfileFlags(app *kingpin.CmdClause) {
	app.Flag("profiling", "If true, do profiling").BoolVar(&f.Profile.IsProfiling)
	app.Flag("logging", "If true, do logging").BoolVar(&f.Profile.IsLogging)
}
