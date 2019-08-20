package wireray

import (
	"io"
	"os"

	"github.com/tkuchiki/wireray/helpers"

	stats_flags "github.com/tkuchiki/alp/flags"

	"github.com/tkuchiki/wireray/options"

	stats_options "github.com/tkuchiki/alp/options"
	"github.com/tkuchiki/wireray/flags"

	"github.com/tkuchiki/alp/stats"
	"gopkg.in/alecthomas/kingpin.v2"
)

const version = "0.1.0"

type Profiler struct {
	outWriter    io.Writer
	errWriter    io.Writer
	inReader     *os.File
	optionParser *kingpin.Application
	flags        *flags.Flags
}

func NewProfiler(outw, errw io.Writer) (*Profiler, error) {
	p := &Profiler{
		outWriter:    outw,
		errWriter:    errw,
		inReader:     os.Stdin,
		optionParser: kingpin.New("wireray", "HTTP profiler"),
	}

	iface, err := helpers.GetLoopbakInterface()
	if err != nil {
		return nil, err
	}

	p.flags = flags.NewFlags(iface)
	p.flags.InitCommonFlags(p.optionParser)

	p.flags.Stats = stats_flags.NewGlobalFlags()
	p.flags.Stats.InitGlobalFlags(p.optionParser)

	_ = p.optionParser.Command("capture", "Record pcap file")
	_ = p.optionParser.Command("logging", "Logging")
	_ = p.optionParser.Command("profiling", "Profiling")

	return p, nil
}

func (p *Profiler) SetFlags(flags *flags.Flags) {
	p.flags = flags
}

func (p *Profiler) SetInReader(f *os.File) {
	p.inReader = f
}

func (p *Profiler) Open(filename string) (*os.File, error) {
	var f *os.File
	var err error

	if filename != "" {
		f, err = os.Open(filename)
	} else {
		f = p.inReader
	}

	return f, err
}

func (p *Profiler) Run() error {
	p.optionParser.Version(version)
	subcmd, err := p.optionParser.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	sort := stats_flags.SortOptions[p.flags.Stats.Sort]

	var opts *options.Options
	if p.flags.Stats.Config != "" {
		cf, err := os.Open(p.flags.Stats.Config)
		if err != nil {
			return err
		}
		defer cf.Close()

		opts, err = options.LoadOptionsFromReader(cf)
		if err != nil {
			return err
		}
	} else {
		opts = options.NewOptions()
	}

	opts = options.SetOptions(opts,
		options.Snaplen(p.flags.Common.Snaplen),
		options.Iface(p.flags.Common.Iface),
		options.Port(p.flags.Common.Port),
		options.Pcap(p.flags.Common.Pcap),
		options.Lazy(p.flags.Common.Lazy),
		options.Body(p.flags.Common.Body),
		options.Gunzip(p.flags.Common.Gunzip),
	)

	opts.StatsOptions = stats_options.SetOptions(opts.StatsOptions,
		stats_options.File(p.flags.Stats.File),
		stats_options.Sort(sort),
		stats_options.Reverse(p.flags.Stats.Reverse),
		stats_options.QueryString(p.flags.Stats.QueryString),
		stats_options.Format(p.flags.Stats.Format),
		stats_options.Limit(p.flags.Stats.Limit),
		stats_options.Location(p.flags.Stats.Location),
		stats_options.Output(p.flags.Stats.Output),
		stats_options.NoHeaders(p.flags.Stats.NoHeaders),
		stats_options.ShowFooters(p.flags.Stats.ShowFooters),
		stats_options.CSVGroups(p.flags.Stats.MatchingGroups),
		stats_options.Filters(p.flags.Stats.Filters),
	)

	sts := stats.NewHTTPStats(true, false, false)

	err = sts.InitFilter(opts.StatsOptions)
	if err != nil {
		return err
	}

	sts.SetOptions(opts.StatsOptions)

	printer := stats.NewPrinter(p.outWriter, opts.StatsOptions.Output, opts.StatsOptions.Format, opts.StatsOptions.NoHeaders, opts.StatsOptions.ShowFooters)
	if err = printer.Validate(); err != nil {
		return err
	}

	if len(opts.StatsOptions.MatchingGroups) > 0 {
		err = sts.SetURIMatchingGroups(opts.StatsOptions.MatchingGroups)
		if err != nil {
			return err
		}
	}

	profiler := NewHTTPProfiler(opts, sts, printer)

	switch subcmd {
	case "capture":
		return profiler.WritePcap(opts.Pcap)
	case "profiling":
		return profiler.Profile()
	case "logging":
		return profiler.LiveLogging()
	}

	return nil
}
