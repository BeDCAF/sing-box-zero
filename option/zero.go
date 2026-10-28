package option

type ZeroInboundOptions struct {
	ListenOptions
	Users      []ZeroUser `json:"users,omitempty"`
	Decryption string     `json:"decryption,omitempty"`
	InboundTLSOptionsContainer
	Fallback        *ServerOptions            `json:"fallback,omitempty"`
	FallbackForALPN map[string]*ServerOptions `json:"fallback_for_alpn,omitempty"`
	Multiplex       *InboundMultiplexOptions  `json:"multiplex,omitempty"`
	Transport       *V2RayTransportOptions    `json:"transport,omitempty"`
}

type ZeroUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type ZeroOutboundOptions struct {
	DialerOptions
	ServerOptions
	Password   string      `json:"password"`
	Network    NetworkList `json:"network,omitempty"`
	Vision     bool        `json:"vision,omitempty"`
	Encryption string      `json:"encryption,omitempty"`
	OutboundTLSOptionsContainer
	UDPOverTCP *UDPOverTCPOptions        `json:"udp_over_tcp,omitempty"`
	Multiplex  *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport  *V2RayTransportOptions    `json:"transport,omitempty"`
}
