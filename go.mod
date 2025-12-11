module go.arwos.org/casper

go 1.25.3

require (
	github.com/google/uuid v1.6.0
	go.arwos.org/casper/client v0.0.0
	go.osspkg.com/console v0.3.3
	go.osspkg.com/do v0.2.1
	go.osspkg.com/encrypt v0.5.1
	go.osspkg.com/errors v0.4.0
	go.osspkg.com/events v0.3.0
	go.osspkg.com/goppy/v2 v2.4.6
	go.osspkg.com/ioutils v0.7.3
	go.osspkg.com/logx v0.6.0
	go.osspkg.com/routine v0.4.0
	go.osspkg.com/syncing v0.4.3
	go.osspkg.com/validate v0.1.0
	go.osspkg.com/xc v0.4.0
)

replace go.arwos.org/casper/client => ./client

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/BurntSushi/toml v1.5.0 // indirect
	github.com/go-sql-driver/mysql v1.9.3 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/mailru/easyjson v0.9.1 // indirect
	github.com/quic-go/quic-go v0.57.0 // indirect
	go.osspkg.com/algorithms v1.6.0 // indirect
	go.osspkg.com/config v0.2.0 // indirect
	go.osspkg.com/grape v1.3.0 // indirect
	go.osspkg.com/network v0.6.0 // indirect
	go.osspkg.com/random v0.5.0 // indirect
	go.osspkg.com/static v1.4.0 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
