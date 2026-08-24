package model

// SSH Manager models.
//
// These tables are additive to the stock 4x-ui schema and are registered in
// database/db.go initModels(). They never alter existing Xray/inbound tables.

// SSH inbound modes.
const (
	SshModeNormal      = "normal_ssh"       // client -> OpenSSH directly on the public port
	SshModeTlsSni      = "ssh_tls_sni"      // client -> TLS(public) -> stunnel -> OpenSSH backend
	SshModeTlsPayload  = "ssh_tls_payload"  // client -> TLS(public) -> stunnel -> payload gateway -> OpenSSH backend
	SshModePayloadOnly = "ssh_payload_only" // client -> plain TCP payload gateway (no TLS) -> OpenSSH backend
)

// SSH certificate modes (only relevant for the TLS modes).
const (
	SshCertSelfSigned = "self_signed"
	SshCertExisting   = "existing"
)

// SshInbound represents a single SSH access endpoint managed by the panel.
//
// Port semantics by mode:
//   - normal_ssh:      ListenPort is the public OpenSSH port. BackendSshPort is ignored (mirrored to ListenPort).
//   - ssh_tls_sni:     ListenPort is the public TLS port (stunnel). BackendSshPort is the local OpenSSH port.
//   - ssh_tls_payload: ListenPort is the public TLS port (stunnel). GatewayPort is the local payload gateway
//     (auto-assigned when 0). BackendSshPort is the local OpenSSH port.
type SshInbound struct {
	Id             int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Name           string `json:"name" form:"name"`
	Mode           string `json:"mode" form:"mode"`
	Host           string `json:"host" form:"host"`
	ListenPort     int    `json:"listenPort" form:"listenPort"`
	BackendSshPort int    `json:"backendSshPort" form:"backendSshPort"`
	GatewayPort    int    `json:"gatewayPort" form:"gatewayPort"`
	UdpRelayPort   int    `json:"udpRelayPort" form:"udpRelayPort"`
	Banner         string `json:"banner" form:"banner"`
	CertMode       string `json:"certMode" form:"certMode"`
	CertFile       string `json:"certFile" form:"certFile"`
	KeyFile        string `json:"keyFile" form:"keyFile"`
	Enable         bool   `json:"enable" form:"enable"`
	Note           string `json:"note" form:"note"`
	CreatedAt      int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt      int64  `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

func (SshInbound) TableName() string { return "ssh_inbounds" }

// SshUser represents a Linux SSH login account managed by the panel.
//
// The plaintext password is never stored. PasswordEnc holds an AES-GCM
// ciphertext (keyed from the panel secret) so the panel can render the
// HOST:PORT@USER:PASS client string on demand. The real credential lives only
// in /etc/shadow on the host, set via chpasswd over stdin.
type SshUser struct {
	Id            int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Username      string `json:"username" form:"username" gorm:"unique"`
	PasswordEnc   string `json:"-"`                                 // AES-GCM, base64; never serialised to clients
	Password      string `json:"password" form:"password" gorm:"-"` // transient: inbound from form / outbound for display only
	Enable        bool   `json:"enable" form:"enable"`
	ExpiryTime    int64  `json:"expiryTime" form:"expiryTime"` // unix ms, 0 = never
	Note          string `json:"note" form:"note"`
	TrafficLimit  int64  `json:"trafficLimit" form:"trafficLimit"` // bytes, 0 = unlimited
	TrafficUsed   int64  `json:"trafficUsed" form:"trafficUsed"`
	ResetFlow     string `json:"resetFlow" form:"resetFlow"` // never, daily, weekly, monthly
	LastResetTime int64  `json:"lastResetTime" form:"lastResetTime"`
	SpeedLimit    bool   `json:"speedLimit" form:"speedLimit"`
	DownloadMbps  int    `json:"downloadMbps" form:"downloadMbps"`
	UploadMbps    int    `json:"uploadMbps" form:"uploadMbps"`
	CreatedAt     int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt     int64  `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

func (SshUser) TableName() string { return "ssh_users" }
