package httpprof

import (
	"os"

	// pulls in all layers decoders

	"github.com/tkuchiki/gohttpstats"
	"gopkg.in/alecthomas/kingpin.v2"
)

func Run() error {
	var app = kingpin.New("httpprof", "HTTP profiler")
	var snaplen = app.Flag("snaplen", "Snap length (number of bytes max to read per packet").Default("65536").Int()
	var iface = app.Flag("iface", "Interface to read packets from").Default("lo0").String()
	var port = app.Flag("port", "Port").Required().Int()
	var pfile = app.Flag("pcap", "Pcap file").String()
	var lazy = app.Flag("lazy", "If true, do lazy decoding").Bool()

	_ = app.Command("live", "Live profile")
	_ = app.Command("pcap", "Profiling pcap file")
	_ = app.Command("capture", "Record pcap file")
	_ = app.Command("live_logging", "Live logging")

	app.Version("0.1.0")

	subcmd := kingpin.MustParse(app.Parse(os.Args[1:]))

	config := NewConfig(*iface, *snaplen, *port, *lazy)
	po := httpstats.NewPrintOption()
	profiler := NewHTTPProfiler(config, po)

	switch subcmd {
	case "capture":
		return profiler.WritePcap(*pfile)
	case "live":
		return profiler.LiveProfile()
	case "pcap":
		return profiler.Profile(*pfile)
	case "live_logging":
		return profiler.LiveLogging()
	}

	return nil
}
