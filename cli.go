package wireray

import (
	"io"
	"os"

	"github.com/tkuchiki/wireray/options"

	"github.com/tkuchiki/gohttpstats/options"
	"github.com/tkuchiki/wireray/flag"

	"github.com/tkuchiki/gohttpstats"
	"gopkg.in/alecthomas/kingpin.v2"
)

const version = "0.0.1"

type Profiler struct {
	outWriter    io.Writer
	errWriter    io.Writer
	inReader     *os.File
	optionParser *kingpin.Application
	flags        *flag.Flags
}

func NewProfiler(outw, errw io.Writer) *Profiler {
	p := &Profiler{
		outWriter:    outw,
		errWriter:    errw,
		inReader:     os.Stdin,
		optionParser: kingpin.New("wireray", "HTTP profiler"),
	}
	p.flags = flag.NewFlags()

	p.flags.InitCommonFlags(p.optionParser)

	_ = p.optionParser.Command("capture", "Record pcap file")
	_ = p.optionParser.Command("logging", "Logging")
	profile := p.optionParser.Command("profiling", "Profiling")

	p.flags.InitProfileFlags(profile)

	return p
}

func (p *Profiler) SetFlags(flags *flag.Flags) {
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

	var sort string
	if p.flags.Stats.Max {
		sort = httpstats.SortMaxResponseTime
	} else if p.flags.Stats.Min {
		sort = httpstats.SortMinResponseTime
	} else if p.flags.Stats.Avg {
		sort = httpstats.SortAvgResponseTime
	} else if p.flags.Stats.Sum {
		sort = httpstats.SortSumResponseTime
	} else if p.flags.Stats.Cnt {
		sort = httpstats.SortCount
	} else if p.flags.Stats.P1 {
		sort = httpstats.SortP1ResponseTime
	} else if p.flags.Stats.P50 {
		sort = httpstats.SortP50ResponseTime
	} else if p.flags.Stats.P99 {
		sort = httpstats.SortP99ResponseTime
	} else if p.flags.Stats.Stddev {
		sort = httpstats.SortStddevResponseTime
	} else if p.flags.Stats.SortUri {
		sort = httpstats.SortUri
	} else if p.flags.Stats.Method {
		sort = httpstats.SortMethod
	} else if p.flags.Stats.MaxBody {
		sort = httpstats.SortMaxResponseBodySize
	} else if p.flags.Stats.MinBody {
		sort = httpstats.SortMinResponseBodySize
	} else if p.flags.Stats.AvgBody {
		sort = httpstats.SortAvgResponseBodySize
	} else if p.flags.Stats.SumBody {
		sort = httpstats.SortSumResponseBodySize
	} else {
		sort = httpstats.SortMaxResponseTime
	}

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
	)

	opts.StatsOptions = stats_options.SetOptions(opts.StatsOptions,
		stats_options.File(p.flags.Stats.File),
		stats_options.Sort(sort),
		stats_options.Reverse(p.flags.Stats.Reverse),
		stats_options.QueryString(p.flags.Stats.QueryString),
		stats_options.Tsv(p.flags.Stats.Tsv),
		stats_options.ApptimeLabel(p.flags.Stats.ApptimeLabel),
		stats_options.ReqtimeLabel(p.flags.Stats.ReqtimeLabel),
		stats_options.StatusLabel(p.flags.Stats.StatusLabel),
		stats_options.SizeLabel(p.flags.Stats.SizeLabel),
		stats_options.MethodLabel(p.flags.Stats.MethodLabel),
		stats_options.UriLabel(p.flags.Stats.UriLabel),
		stats_options.TimeLabel(p.flags.Stats.TimeLabel),
		stats_options.Limit(p.flags.Stats.Limit),
		stats_options.NoHeaders(p.flags.Stats.NoHeaders),
		stats_options.StartTime(p.flags.Stats.StartTime),
		stats_options.EndTime(p.flags.Stats.EndTime),
		stats_options.StartTimeDuration(p.flags.Stats.StartTimeDuration),
		stats_options.EndTimeDuration(p.flags.Stats.EndTimeDuration),
		stats_options.CSVIncludes(p.flags.Stats.Includes),
		stats_options.CSVExcludes(p.flags.Stats.Excludes),
		stats_options.CSVIncludeStatuses(p.flags.Stats.IncludeStatuses),
		stats_options.CSVExcludeStatuses(p.flags.Stats.ExcludeStatuses),
		stats_options.CSVAggregates(p.flags.Stats.Aggregates),
	)

	po := httpstats.NewPrintOptions()
	po.SetWriter(p.outWriter)
	if opts.StatsOptions.Tsv {
		po.SetFormat("tsv")
	}
	stats := httpstats.NewHTTPStats(true, false, false, po)

	err = stats.InitFilter(opts.StatsOptions)
	if err != nil {
		return err
	}

	stats.SetOptions(opts.StatsOptions)

	//if p.flags.Profile.IsProfiling || p.flags.Profile.IsLogging {
	//	return fmt.Errorf("--profile or --logging is required")
	//}

	if len(opts.StatsOptions.Aggregates) > 0 {
		err = stats.SetURICapturingGroups(opts.StatsOptions.Aggregates)
		if err != nil {
			return err
		}
	}

	profiler := NewHTTPProfiler(opts, stats)

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
