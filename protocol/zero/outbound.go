package zero

import (
	"context"
	"encoding/base64"
	"net"
	"strings"

	zero "github.com/BeDCAF/Zero"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/zero/encryption"
	"github.com/sagernet/sing-box/transport/v2ray"
	singmux "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.ZeroOutboundOptions](registry, C.TypeZero, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	serverAddr      M.Socksaddr
	key             [zero.KeyLength]byte
	vision          bool
	encryption      *encryption.ClientInstance
	multiplexDialer *mux.Client
	uotClient       *uot.Client
	tlsConfig       tls.Config
	tlsDialer       tls.Dialer
	transport       adapter.V2RayClientTransport
}

func NewOutbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.ZeroOutboundOptions,
) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	out := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeZero, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		key:        zero.Key(options.Password),
		vision:     options.Vision,
	}

	if options.TLS != nil {
		out.tlsConfig, err = tls.NewClientWithOptions(tls.ClientOptions{
			Context:        ctx,
			Logger:         logger,
			ServerAddress:  options.Server,
			Options:        common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" && !common.PtrValueOrDefault(options.Multiplex).Enabled,
		})
		if err != nil {
			return nil, err
		}
		out.tlsDialer = tls.NewDialer(outboundDialer, out.tlsConfig)
	}

	if options.Transport != nil {
		out.transport, err = v2ray.NewClientTransport(ctx, out.dialer, out.serverAddr, common.PtrValueOrDefault(options.Transport), out.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}

	if options.Vision {
		if options.TLS == nil || !options.TLS.Enabled {
			return nil, E.New("zero: vision requires TLS enabled")
		}
		if options.Transport != nil {
			return nil, E.New("zero: vision is incompatible with transport")
		}
		if common.PtrValueOrDefault(options.Multiplex).Enabled {
			return nil, E.New("zero: vision is incompatible with multiplex")
		}

		if options.Encryption != "" && options.Encryption != "none" {
			return nil, E.New("zero: vision is incompatible with encryption (not yet supported)")
		}
	}

	if options.Encryption != "" && options.Encryption != "none" {
		encCfg, err := parseClientEncryption(options.Encryption)
		if err != nil {
			return nil, E.Cause(err, "parse encryption")
		}
		out.encryption = &encryption.ClientInstance{}
		if err := out.encryption.Init(encCfg.keys, encCfg.xorMode, encCfg.seconds, encCfg.padding); err != nil {
			return nil, E.Cause(err, "initialize encryption")
		}
		logger.Debug("zero encryption initialized: keys=", len(encCfg.keys),
			" xorMode=", encCfg.xorMode, " seconds=", encCfg.seconds, " padding=", encCfg.padding)
	}

	if uotOpts := common.PtrValueOrDefault(options.UDPOverTCP); uotOpts.Enabled {
		out.uotClient = &uot.Client{
			Dialer:  (*zeroDialer)(out),
			Version: uotOpts.Version,
		}
	}

	out.multiplexDialer, err = mux.NewClientWithOptions((*zeroDialer)(out), logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		if h.multiplexDialer != nil {
			h.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
			return h.multiplexDialer.DialContext(ctx, network, destination)
		}
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return (*zeroDialer)(h).DialContext(ctx, network, destination)

	case N.NetworkUDP:
		if h.uotClient != nil {
			h.logger.InfoContext(ctx, "outbound UoT connection to ", destination)
			return h.uotClient.DialContext(ctx, network, destination)
		}
		if h.multiplexDialer != nil {
			h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
			return h.multiplexDialer.DialContext(ctx, network, destination)
		}
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return (*zeroDialer)(h).DialContext(ctx, network, destination)

	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.uotClient != nil {
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.ListenPacket(ctx, destination)
	}
	if h.multiplexDialer != nil {
		h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		return h.multiplexDialer.ListenPacket(ctx, destination)
	}
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return (*zeroDialer)(h).ListenPacket(ctx, destination)
}

func (h *Outbound) MultiplexEnabled() bool {
	if h.multiplexDialer != nil {
		return true
	}
	mt, ok := h.transport.(adapter.V2RayMultiplexClientTransport)
	return ok && mt.MultiplexEnabled()
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	if tk, ok := h.transport.(adapter.IdleConnectionKeeper); ok {
		tk.SetKeepIdleConnections(keep)
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.SetKeepIdleConnections(keep)
	}
}

func (h *Outbound) CloseIdleConnections() {
	if tk, ok := h.transport.(adapter.IdleConnectionKeeper); ok {
		tk.CloseIdleConnections()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.CloseIdleConnections()
	}
}

func (h *Outbound) Close() error {
	return common.Close(common.PtrOrNil(h.multiplexDialer), h.transport)
}

var _ N.Dialer = (*zeroDialer)(nil)

type zeroDialer Outbound

func (h *zeroDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else if h.tlsDialer != nil {
		conn, err = h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	}
	if err != nil {
		common.Close(conn)
		return nil, err
	}

	if h.encryption != nil {
		encConn, encErr := h.encryption.Handshake(conn)
		if encErr != nil {
			common.Close(conn)
			return nil, E.Cause(encErr, "encryption handshake")
		}
		conn = encConn
	}

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		var command byte
		if destination.IsDomain() && destination.Fqdn == uot.MagicAddress {
			command = zero.CommandUDP
		} else if destination.IsDomain() && destination.Fqdn == singmux.Destination.Fqdn {
			command = zero.CommandMux
		} else {
			command = zero.CommandTCP
		}

		if h.vision && command == zero.CommandTCP {
			if h.transport != nil {
				common.Close(conn)
				return nil, E.New("zero: vision is incompatible with transport")
			}
			if h.tlsDialer == nil {
				common.Close(conn)
				return nil, E.New("zero: vision requires TLS")
			}
			visionConn, err := zero.NewVisionClientConn(conn, conn, h.key, destination, h.logger)
			if err != nil {
				common.Close(conn)
				return nil, E.Cause(err, "initialize vision")
			}
			return visionConn, nil
		}

		return zero.NewClientConn(conn, h.key, command, destination), nil

	case N.NetworkUDP:
		if destination.IsDomain() && destination.Fqdn == singmux.Destination.Fqdn {
			return zero.NewClientConn(conn, h.key, zero.CommandMux, destination), nil
		}
		return bufio.NewBindPacketConn(zero.NewClientPacketConn(conn, h.key), destination), nil

	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *zeroDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := h.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return conn.(net.PacketConn), nil
}

type clientEncryptionConfig struct {
	keys    [][]byte
	xorMode uint32
	seconds uint32
	padding string
}

func parseClientEncryption(raw string) (clientEncryptionConfig, error) {
	var cfg clientEncryptionConfig
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cfg, E.New("empty encryption string")
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 4 {
		return cfg, E.New("invalid encryption string: missing components")
	}
	if parts[0] != "mlkem768x25519plus" {
		return cfg, E.New("unsupported encryption prefix: ", parts[0])
	}
	switch parts[1] {
	case "native":
		cfg.xorMode = 0
	case "xorpub":
		cfg.xorMode = 1
	case "random":
		cfg.xorMode = 2
	default:
		return cfg, E.New("unknown encryption mode: ", parts[1])
	}
	switch parts[2] {
	case "0rtt":
		cfg.seconds = 1
	case "1rtt":
		cfg.seconds = 0
	default:
		return cfg, E.New("unsupported encryption RTT value: ", parts[2])
	}
	paddingPhase := true
	var paddingParts []string
	for _, segment := range parts[3:] {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return cfg, E.New("invalid empty segment in encryption string")
		}
		if data, err := base64.RawURLEncoding.DecodeString(segment); err == nil {
			if len(data) == 32 || len(data) == 1184 {
				cfg.keys = append(cfg.keys, data)
				paddingPhase = false
				continue
			}
			return cfg, E.New("invalid encryption key length: ", len(data))
		}
		if paddingPhase {
			paddingParts = append(paddingParts, segment)
			continue
		}
		return cfg, E.New("invalid encryption key: ", segment)
	}
	if len(cfg.keys) == 0 {
		return cfg, E.New("no valid encryption keys found in encryption string")
	}
	if len(paddingParts) > 0 {
		cfg.padding = strings.Join(paddingParts, ".")
	}
	return cfg, nil
}
