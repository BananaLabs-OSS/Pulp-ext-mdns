// Package mdnsext provides the discovery.mdns capability for Pulp cells: LAN
// peer discovery over mDNS/zeroconf. A cell can't open a raw UDP multicast
// socket (it's sandboxed), so the host does it here via grandcat/zeroconf —
// browse the LAN for a service, and announce this instance for others to find.
//
// This is the one piece of the multi-machine fleet that genuinely needs a new
// host capability (UDP multicast on 224.0.0.251:5353); everything else ports
// over fs / http.outbound.
//
// Deployment:
//
//	import _ "github.com/BananaLabs-OSS/Pulp-ext-mdns"
//
// Host imports:
//
//	mdns_browse(req_ptr, req_len, resp_ptr_out, resp_len_out) -> code  # req{service,timeout_ms}; resp [{name,addr}]
//	mdns_announce(req_ptr, req_len) -> code                            # req{instance,service,port}
package mdnsext

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/grandcat/zeroconf"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	codeOK          = 0
	codeMemRead     = 2
	codeDecode      = 3
	codeBrowseFail  = 4
	codeAllocFailed = 7
	codeMemWrite    = 8
	codeCapAbsent   = 99

	maxBrowseTimeout = 10 * time.Second
)

var (
	logger    = slog.Default()
	announceM sync.Mutex
	announced []*zeroconf.Server // kept alive for the host lifetime
)

func init() {
	ext.Register(ext.Capability{
		Name:     "discovery.mdns",
		Setup:    func(env ext.SetupEnv) error { if env.Logger != nil { logger = env.Logger }; return nil },
		Teardown: teardown,
		Register: bindActive,
		Stub:     bindStub,
	})
}

func teardown(_ context.Context) error {
	announceM.Lock()
	defer announceM.Unlock()
	for _, s := range announced {
		s.Shutdown()
	}
	announced = nil
	return nil
}

func bindActive(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
		return mdnsBrowse(ctx, m, reqPtr, reqLen, respPtrOut, respLenOut)
	}).Export("mdns_browse")
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
		return mdnsAnnounce(m, reqPtr, reqLen)
	}).Export("mdns_announce")
	return nil
}

func bindStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return codeCapAbsent }).Export("mdns_browse")
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return codeCapAbsent }).Export("mdns_announce")
	return nil
}

type entry struct {
	Name string `msgpack:"name"`
	Addr string `msgpack:"addr"`
}

func mdnsBrowse(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	var req struct {
		Service   string `msgpack:"service"`
		TimeoutMs uint32 `msgpack:"timeout_ms"`
	}
	if reqLen > 0 {
		data, ok := m.Memory().Read(reqPtr, reqLen)
		if !ok {
			return codeMemRead
		}
		if err := msgpack.Unmarshal(data, &req); err != nil {
			return codeDecode
		}
	}
	if req.Service == "" {
		req.Service = "_projx._tcp"
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 || timeout > maxBrowseTimeout {
		timeout = 2500 * time.Millisecond
	}
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return codeBrowseFail
	}
	entries := make(chan *zeroconf.ServiceEntry, 16)
	bctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := resolver.Browse(bctx, req.Service, "local.", entries); err != nil {
		return codeBrowseFail
	}
	var out []entry
	for e := range entries {
		if len(e.AddrIPv4) == 0 {
			continue
		}
		out = append(out, entry{Name: e.Instance, Addr: fmt.Sprintf("http://%s:%d", e.AddrIPv4[0].String(), e.Port)})
	}
	payload, err := msgpack.Marshal(out)
	if err != nil {
		return codeAllocFailed
	}
	return writeResp(ctx, m, payload, respPtrOut, respLenOut)
}

func mdnsAnnounce(m api.Module, reqPtr, reqLen uint32) uint32 {
	var req struct {
		Instance string `msgpack:"instance"`
		Service  string `msgpack:"service"`
		Port     uint32 `msgpack:"port"`
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return codeMemRead
	}
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return codeDecode
	}
	if req.Service == "" {
		req.Service = "_projx._tcp"
	}
	if req.Instance == "" {
		req.Instance = "projx"
	}
	server, err := zeroconf.Register(req.Instance, req.Service, "local.", int(req.Port), nil, nil)
	if err != nil {
		logger.Error("mdns announce", "err", err)
		return codeBrowseFail
	}
	announceM.Lock()
	announced = append(announced, server)
	announceM.Unlock()
	return codeOK
}

func writeResp(ctx context.Context, m api.Module, data []byte, respPtrOut, respLenOut uint32) uint32 {
	allocFn := m.ExportedFunction("pulp_alloc")
	if allocFn == nil {
		return codeAllocFailed
	}
	res, err := allocFn.Call(ctx, uint64(len(data)))
	if err != nil || len(res) == 0 {
		return codeAllocFailed
	}
	ptr := uint32(res[0])
	if ptr == 0 || !m.Memory().Write(ptr, data) {
		return codeMemWrite
	}
	if !m.Memory().WriteUint32Le(respPtrOut, ptr) || !m.Memory().WriteUint32Le(respLenOut, uint32(len(data))) {
		return codeMemWrite
	}
	return codeOK
}
