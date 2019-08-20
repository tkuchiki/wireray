package flags

import (
	stats_flags "github.com/tkuchiki/alp/flags"
	"gopkg.in/alecthomas/kingpin.v2"
)

type Flags struct {
	Common       *Common
	Stats        *stats_flags.GlobalFlags
	defaultIface string
}

type Common struct {
	Snaplen int
	Iface   string
	Port    int
	Pcap    string
	Lazy    bool
	Body    bool
	Gunzip  bool
}

func NewFlags(iface string) *Flags {
	return &Flags{
		Common:       &Common{},
		Stats:        stats_flags.NewGlobalFlags(),
		defaultIface: iface,
	}
}

func (f *Flags) InitCommonFlags(app *kingpin.Application) {
	app.Flag("snaplen", "Snap length (number of bytes max to read per packet").Default("65536").IntVar(&f.Common.Snaplen)
	app.Flag("iface", "Interface to read packets from").Default(f.defaultIface).StringVar(&f.Common.Iface)
	app.Flag("port", "Port").Required().IntVar(&f.Common.Port)
	app.Flag("pcap", "Pcap file").StringVar(&f.Common.Pcap)
	app.Flag("lazy", "If true, do lazy decoding").BoolVar(&f.Common.Lazy)
	app.Flag("body", "If true, dump http body").BoolVar(&f.Common.Body)
	app.Flag("gunzip", "If true, decompress gzipped http body").BoolVar(&f.Common.Gunzip)

}
