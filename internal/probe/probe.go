package probe

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gabspt/ConnectionStats/clsact"
	"github.com/gabspt/ConnectionStats/internal/timer"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/connstats_dynamic_time_tcpreplay.c - -O3  -Wall -Werror -Wno-address-of-packed-member

const tenMegaBytes = 1024 * 1024 * 10      // 10MB
const twentyMegaBytes = tenMegaBytes * 2   // 20MB
const fortyMegaBytes = twentyMegaBytes * 2 // 40MB

const TCP_IDLE_TIME = 300000000000 //300000ms = 5min
const UDP_IDLE_TIME = 200000000000 //200000ms = 3min and 20s
const SINGLETON_TIME = 10000000000 //10000ms = 10s

const scaleFactor = 1000

var ipProtoNums = map[uint8]string{
	6:  "TCP",
	17: "UDP",
}

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	bpfObjects *probeObjects
	filters    []*netlink.BpfFilter
}

func setRlimit() error {
	//log.Printf("Setting rlimit - soft: %v, hard: %v", twentyMegaBytes, fortyMegaBytes)

	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: tenMegaBytes,
		Max: fortyMegaBytes,
	})
}

func (p *probe) loadObjects() error {
	//log.Printf("Loading probe object to kernel")

	objs := probeObjects{}

	if err := loadProbeObjects(&objs, nil); err != nil {
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func (p *probe) createQdisc() error {
	//log.Printf("Creating qdisc")

	p.qdisc = clsact.NewClsAct(&netlink.QdiscAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	})

	if err := p.handle.QdiscAdd(p.qdisc); err != nil {
		if err := p.handle.QdiscReplace(p.qdisc); err != nil {
			return err
		}
	}

	return nil
}

func (p *probe) createFilters() error {
	//log.Printf("Creating qdisc filters")

	addFilterin := func(attrs netlink.FilterAttrs) {
		p.filters = append(p.filters, &netlink.BpfFilter{
			FilterAttrs:  attrs,
			Fd:           p.bpfObjects.probePrograms.Connstatsin.FD(),
			DirectAction: true,
		})
	}

	addFilterin(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilterin(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IPV6,
	})

	for _, filter := range p.filters {
		if err := p.handle.FilterAdd(filter); err != nil {
			if err := p.handle.FilterReplace(filter); err != nil {
				return err
			}
		}
	}

	return nil
}

func newProbe(iface netlink.Link) (*probe, error) {
	//log.Println("Creating a new probe")

	if err := setRlimit(); err != nil {
		log.Printf("Failed setting rlimit: %v", err)
		return nil, err
	}

	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)

	if err != nil {
		log.Printf("Failed getting netlink handle: %v", err)
		return nil, err
	}

	prbe := probe{
		iface:  iface,
		handle: handle,
	}

	if err := prbe.loadObjects(); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.createQdisc(); err != nil {
		log.Printf("Failed creating qdisc: %v", err)
		return nil, err
	}

	if err := prbe.createFilters(); err != nil {
		log.Printf("Failed creating qdisc filters: %v", err)
		return nil, err
	}

	return &prbe, nil
}

// func print global metrics
func (p *probe) PrintGlobalMetrics() {
	globalmetricsmap := p.bpfObjects.probeMaps.Globalmetrics
	keyg := uint32(0)
	var gm probeGlobalMetrics
	err := globalmetricsmap.Lookup(keyg, &gm)
	if err != nil {
		log.Fatalf("Failed to lookup global metrics: %v", err)
	}

	log.Printf("")
	log.Printf("Global metrics:")
	log.Printf("---------------")
	log.Printf("Total packets processed: %v", gm.TotalProcessedpackets)
	log.Printf("Total packets analyzed (TCP+UDP): %v", gm.TotalTcppackets+gm.TotalUdppackets)
	log.Printf("Total TCP packets analyzed: %v", gm.TotalTcppackets)
	log.Printf("Total UDP packets analyzed: %v", gm.TotalUdppackets)
	//log.Printf("Total flows analyzed: %v", gm.TotalFlows)
	log.Printf("Total TCP flows analyzed: %v", gm.TotalTcpflows)
	log.Printf("Total UDP flows analyzed: %v", gm.TotalUdpflows)
	log.Printf("")
}

func writeFlowStatsToCSV(w *csv.Writer, flowStats probeFlowStats) error {
	// Write the flow stats to the CSV file
	protoc, ok := ipProtoNums[flowStats.FlowTuple.Protocol]
	if !ok {
		log.Print("Failed fetching protocol number: ", flowStats.FlowTuple.Protocol)
	}
	ipAndPortA := fmt.Sprintf("%s:%d", net.IP(flowStats.FlowTuple.A_ip.In6U.U6Addr8[:]).String(), flowStats.FlowTuple.A_port)
	ipAndPortB := fmt.Sprintf("%s:%d", net.IP(flowStats.FlowTuple.B_ip.In6U.U6Addr8[:]).String(), flowStats.FlowTuple.B_port)

	record := []string{
		protoc,
		ipAndPortA,
		ipAndPortB,
		//strconv.Itoa(int(flowStats.PacketsIn)),
		//strconv.Itoa(int(flowStats.PacketsOut)),
		//strconv.Itoa(int(flowStats.BytesIn)),
		//strconv.Itoa(int(flowStats.BytesOut)),
		//strconv.FormatFloat(float64(flowStats.TsCurrent-flowStats.TsStart), 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Inpps)/scaleFactor, 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Outpps)/scaleFactor, 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Inbpp)/scaleFactor, 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Outbpp)/scaleFactor, 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Inboutb)/scaleFactor, 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Inpoutp)/scaleFactor, 'f', 3, 64),
	}

	err := w.Write(record)
	if err != nil {
		return err
	}

	return nil
}

// func writeBlankLineToFile(w *csv.Writer) error {
// 	// Write a blank line to the log file
// 	err := w.Write([]string{"", "", "", "", "", "", "", ""})
// 	if err != nil {
// 		log.Printf("Failed to write to CSV: %v", err)
// 	}
// 	return err
// }

func GenerateStats(ft *FlowTable, w *csv.Writer) {
	ft.Range(func(key, value interface{}) bool {
		flowStats := value.(probeFlowStats)
		if err := writeFlowStatsToCSV(w, flowStats); err != nil {
			log.Println(err)
		}
		return true
	})
	// if err := writeBlankLineToFile(w); err != nil {
	// 	log.Println(err)
	// }
	w.Flush()
}

func (p *probe) Close() error {

	p.PrintGlobalMetrics()

	log.Println("Removing qdisc")
	if err := p.handle.QdiscDel(p.qdisc); err != nil {
		log.Println("Failed deleting qdisc")
		return err
	}

	log.Println("Deleting handle")
	p.handle.Delete()

	log.Println("Closing eBPF object")
	if err := p.bpfObjects.Close(); err != nil {
		log.Println("Failed closing eBPF object")
		return err
	}

	return nil
}

func CheckIfStaleEntry(flowmetrics probeFlowMetrics, lastDuration time.Duration) bool {
	var stale bool
	lastts := flowmetrics.TsCurrent
	now := timer.GetNanosecSinceBoot()
	time_flow := now - lastts
	lastDurationInNanoseconds := uint64(lastDuration.Nanoseconds())
	if (flowmetrics.PacketsIn + flowmetrics.PacketsOut) >= 2 {
		if (flowmetrics.FlowTuple.Protocol == 6) && (time_flow > (TCP_IDLE_TIME - lastDurationInNanoseconds)) {
			stale = true
		} else if (flowmetrics.FlowTuple.Protocol == 17) && (time_flow > (UDP_IDLE_TIME - lastDurationInNanoseconds)) {
			stale = true
		}
	} else if time_flow > (SINGLETON_TIME - lastDurationInNanoseconds) {
		stale = true
	}
	return stale
}

// func EvictMapEntries evicts map entries from the flowstracker map that have been new added or changed and copy to the flowtable
func EvictMapEntries(flowstrackermap *ebpf.Map, ft *FlowTable, lastDuration time.Duration) {
	iterator := flowstrackermap.Iterate()
	var flowhash uint64
	var flowmetrics probeFlowMetrics
	//keysToDelete := []uint64{} // Create a slice to hold the keys to delete
	//iterate over the hash map flowstrackermap
	for iterator.Next(&flowhash, &flowmetrics) {
		ft.Store(flowhash, flowmetrics)
		//luego de updatear el flowtable con los flows del hashmap, hago el prune
		//if CheckIfStaleEntry(flowmetrics, lastDuration) {
		//	keysToDelete = append(keysToDelete, flowhash)
		//}
	}
	//flowstrackermap.BatchDelete(keysToDelete, nil)
	//for _, key := range keysToDelete {
	//	ft.Remove(key) //Delete also from the flowtable o hacer un metodo remove batch
	//}
}

// Run starts the probe
func Run(ctx context.Context, iface netlink.Link, timeAgrupation int64) error {
	//log.Printf("Starting up the probe at interface %v", iface.Attrs().Name)

	probe, err := newProbe(iface)
	if err != nil {
		return err
	}

	flowstatsmap := probe.bpfObjects.probeMaps.Flowstats

	//Open the log file and create a new csv writer writing to the opened file
	filename := "flows_stats_500_10.csv"
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)

	//var mu sync.Mutex

	//evict entries
	tickerevict := time.NewTicker(time.Millisecond * time.Duration(timeAgrupation))
	defer tickerevict.Stop()
	go func() {
		for range tickerevict.C {
			log.Printf("Eviction")
			//mu.Lock()
			//defer mu.Unlock()
			iterator := flowstatsmap.Iterate()
			var newft = NewFlowTable()
			var flowhash uint64
			var flow_stats probeFlowStats
			//keysToDelete := []uint64{} // Create a slice to hold the keys to delete
			//iterate over the hash map flowstrackermap
			for iterator.Next(&flowhash, &flow_stats) {
				newft.Store(flowhash, flow_stats)
				//luego de updatear el flowtable con los flows del hashmap, hago el prune
				// if CheckIfStaleEntry(flow_stats, time.Duration(timeAgrupation)) {
				// 	keysToDelete = append(keysToDelete, flowhash)
				// }
			}
			// flowstatsmap.BatchDelete(keysToDelete, nil)
			// for _, key := range keysToDelete {
			// 	newft.Remove(key) //Delete also from the flowtable o hacer un metodo remove batch
			// }
			GenerateStats(newft, w)
		}
	}()

	// Wait for the context to be done
	for {

		<-ctx.Done()
		//LogFlowTable(ft) //por si queda alguno en la flowtable que no se haya eliminado con el prune y por tanto copiado al logfile
		return probe.Close()
	}
}
