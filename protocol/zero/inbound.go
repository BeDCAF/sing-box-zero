package zero

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"strconv"
	"strings"

	zero "github.com/BeDCAF/Zero"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/zero/encryption"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.ZeroInboundOptions](registry, C.TypeZero, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router                   adapter.ConnectionRouterEx
	logger                   log.ContextLogger
	listener                 *listener.Listener
	service                  *zero.Service[int]
	users                    []option.ZeroUser
	tlsConfig                tls.ServerConfig
	fallbackAddr             M.Socksaddr
	fallbackAddrTLSNextProto map[string]M.Socksaddr
	transport                adapter.V2RayServerTransport
	references               []string
	decryption               *encryption.ServerInstance
	fallbackHandler          N.TCPConnectionHandlerEx
}

func NewInbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.ZeroInboundOptions,
) (adapter.Inbound, error) {
	inb := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeZero, tag),
		router:  router,
		logger:  logger,
		users:   options.Users,
	}

	if options.TLS != nil {
		tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
			Context:        ctx,
			Logger:         logger,
			Options:        common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" && !common.PtrValueOrDefault(options.Multiplex).Enabled,
		})
		if err != nil {
			return nil, err
		}
		inb.tlsConfig = tlsConfig
		if options.TLS.Reality != nil && options.TLS.Reality.Enabled && options.TLS.Reality.Handshake.Detour != "" {
			inb.references = []string{options.TLS.Reality.Handshake.Detour}
		}
	}

	var fallbackHandler N.TCPConnectionHandlerEx
	if options.Fallback != nil && options.Fallback.Server != "" || len(options.FallbackForALPN) > 0 {
		if options.Fallback != nil && options.Fallback.Server != "" {
			inb.fallbackAddr = options.Fallback.Build()
			if !inb.fallbackAddr.IsValid() {
				return nil, E.New("invalid fallback address: ", inb.fallbackAddr)
			}
		}
		if len(options.FallbackForALPN) > 0 {
			if inb.tlsConfig == nil {
				return nil, E.New("fallback for ALPN is not supported without TLS")
			}
			fallbackAddrNextProto := make(map[string]M.Socksaddr)
			for nextProto, destination := range options.FallbackForALPN {
				fallbackAddr := destination.Build()
				if !fallbackAddr.IsValid() {
					return nil, E.New("invalid fallback address for ALPN ", nextProto, ": ", fallbackAddr)
				}
				fallbackAddrNextProto[nextProto] = fallbackAddr
			}
			inb.fallbackAddrTLSNextProto = fallbackAddrNextProto
		}
		fallbackHandler = adapter.NewUpstreamContextHandler(inb.fallbackConnection, nil)
		inb.fallbackHandler = fallbackHandler
	}

	service := zero.NewService[int](
		adapter.NewUpstreamContextHandler(
			inb.newConnection,
			inb.newPacketConnection,
		),
		fallbackHandler,
		logger,
	)

	err := service.UpdateUsers(
		common.MapIndexed(options.Users, func(index int, it option.ZeroUser) int {
			return index
		}),
		common.Map(options.Users, func(it option.ZeroUser) string {
			return it.Password
		}),
	)
	if err != nil {
		return nil, err
	}

	if options.Decryption != "" && options.Decryption != "none" {
		decCfg, err := parseServerDecryption(options.Decryption)
		if err != nil {
			return nil, E.Cause(err, "parse decryption")
		}
		inb.decryption = &encryption.ServerInstance{}
		if err := inb.decryption.Init(decCfg.keys, decCfg.xorMode, decCfg.secondsFrom, decCfg.secondsTo, decCfg.padding); err != nil {
			return nil, E.Cause(err, "initialize decryption")
		}
		logger.Debug("zero decryption initialized: keys=", len(decCfg.keys),
			" xorMode=", decCfg.xorMode,
			" secondsFrom=", decCfg.secondsFrom, " secondsTo=", decCfg.secondsTo,
			" padding=", decCfg.padding)
	}

	if options.Transport != nil {
		inb.transport, err = v2ray.NewServerTransport(ctx, logger, common.PtrValueOrDefault(options.Transport), inb.tlsConfig, (*inboundTransportHandler)(inb))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
	}

	inb.router, err = mux.NewRouterWithOptions(inb.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}

	inb.service = service
	inb.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inb,
	})

	return inb, nil
}

func (h *Inbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	if h.transport == nil {
		return h.listener.Start()
	}
	if common.Contains(h.transport.Network(), N.NetworkTCP) {
		tcpListener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		go func() {
			sErr := h.transport.Serve(tcpListener)
			if sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	if common.Contains(h.transport.Network(), N.NetworkUDP) {
		udpConn, err := h.listener.ListenUDP()
		if err != nil {
			return err
		}
		go func() {
			sErr := h.transport.ServePacket(udpConn)
			if sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	return nil
}

func (h *Inbound) Close() error {
	if h.decryption != nil {
		h.decryption.Close()
	}

	return common.Close(
		h.listener,
		h.tlsConfig,
		h.transport,
	)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil && h.transport == nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}

	if h.decryption != nil {
		var fallback []byte
		encConn, err := h.decryption.Handshake(conn, &fallback)
		if err != nil {
			if h.fallbackHandler != nil && len(fallback) > 0 {
				conn = bufio.NewCachedConn(conn, buf.As(fallback).ToOwned())
				h.fallbackHandler.NewConnectionEx(
					adapter.WithContext(ctx, &metadata),
					conn,
					metadata.Source,
					M.Socksaddr{},
					onClose,
				)
				return
			}
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": encryption handshake"))
			return
		}
		conn = encConn
	}

	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	user := h.users[userIndex].Name
	if user == "" {
		user = F.ToString(userIndex)
	} else {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	user := h.users[userIndex].Name
	if user == "" {
		user = F.ToString(userIndex)
	} else {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) fallbackConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	var fallbackAddr M.Socksaddr
	if len(h.fallbackAddrTLSNextProto) > 0 {
		if tlsConn, loaded := common.Cast[tls.Conn](conn); loaded {
			connectionState := tlsConn.ConnectionState()
			if connectionState.NegotiatedProtocol != "" {
				if fallbackAddr, loaded = h.fallbackAddrTLSNextProto[connectionState.NegotiatedProtocol]; !loaded {
					h.logger.DebugContext(ctx, "process connection from ", metadata.Source, ": fallback disabled for ALPN: ", connectionState.NegotiatedProtocol)
					N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
					return
				}
			}
		}
	}
	if !fallbackAddr.IsValid() {
		if !h.fallbackAddr.IsValid() {
			h.logger.DebugContext(ctx, "process connection from ", metadata.Source, ": fallback disabled by default")
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
			return
		}
		fallbackAddr = h.fallbackAddr
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Destination = fallbackAddr
	h.logger.InfoContext(ctx, "fallback connection to ", fallbackAddr)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

var _ adapter.V2RayServerTransportHandler = (*inboundTransportHandler)(nil)

type inboundTransportHandler Inbound

func (h *inboundTransportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	(*Inbound)(h).NewConnection(ctx, conn, metadata, onClose)
}

func (h *Inbound) References() []string {
	return h.references
}

type serverDecryptionConfig struct {
	keys        [][]byte
	xorMode     uint32
	secondsFrom int64
	secondsTo   int64
	padding     string
}

func parseServerDecryption(raw string) (serverDecryptionConfig, error) {
	var cfg serverDecryptionConfig
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cfg, E.New("empty decryption string")
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 4 {
		return cfg, E.New("invalid decryption string: missing components")
	}
	if parts[0] != "mlkem768x25519plus" {
		return cfg, E.New("unsupported decryption prefix: ", parts[0])
	}
	switch parts[1] {
	case "native":
		cfg.xorMode = 0
	case "xorpub":
		cfg.xorMode = 1
	case "random":
		cfg.xorMode = 2
	default:
		return cfg, E.New("unknown decryption mode: ", parts[1])
	}

	secondsToken := strings.TrimSpace(parts[2])
	if secondsToken == "" {
		return cfg, E.New("invalid decryption seconds segment")
	}
	trimmed := strings.TrimSuffix(secondsToken, "s")
	if trimmed == "" {
		return cfg, E.New("invalid decryption seconds segment")
	}
	values := strings.SplitN(trimmed, "-", 2)
	secondsFrom, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil {
		return cfg, E.Cause(err, "parse decryption seconds_from")
	}
	cfg.secondsFrom = secondsFrom
	if len(values) == 2 && values[1] != "" {
		secondsTo, err := strconv.ParseInt(values[1], 10, 64)
		if err != nil {
			return cfg, E.Cause(err, "parse decryption seconds_to")
		}
		cfg.secondsTo = secondsTo
	}

	paddingPhase := true
	var paddingParts []string
	for _, segment := range parts[3:] {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return cfg, E.New("invalid empty segment in decryption string")
		}
		if data, err := base64.RawURLEncoding.DecodeString(segment); err == nil {
			if len(data) == 32 || len(data) == 64 {
				cfg.keys = append(cfg.keys, data)
				paddingPhase = false
				continue
			}
			return cfg, E.New("invalid decryption key length: ", len(data))
		}
		if paddingPhase {
			paddingParts = append(paddingParts, segment)
			continue
		}
		return cfg, E.New("invalid decryption key: ", segment)
	}
	if len(cfg.keys) == 0 {
		return cfg, E.New("no valid decryption keys found in decryption string")
	}
	if len(paddingParts) > 0 {
		cfg.padding = strings.Join(paddingParts, ".")
	}
	return cfg, nil
}
