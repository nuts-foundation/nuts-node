module github.com/nuts-foundation/nuts-node

// This is the minimal version, the actual go version is determined by the images in the Dockerfile
// This version is used in automated tests such as the 'Scheduled govulncheck' action
go 1.24.0

require (
	github.com/alicebob/miniredis/v2 v2.33.0
	github.com/avast/retry-go/v4 v4.6.0
	github.com/cbroglie/mustache v1.4.0
	github.com/chromedp/chromedp v0.13.0
	github.com/deepmap/oapi-codegen v1.16.2
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/goodsign/monday v1.0.2
	github.com/google/uuid v1.6.0
	github.com/hashicorp/vault/api v1.14.0
	github.com/knadh/koanf v1.5.0
	github.com/labstack/echo/v4 v4.12.0
	github.com/lestrrat-go/jwx v1.2.29
	github.com/magiconair/properties v1.8.7
	github.com/mdp/qrterminal/v3 v3.2.0
	github.com/nats-io/nats-server/v2 v2.10.16
	github.com/nats-io/nats.go v1.35.0
	github.com/nuts-foundation/crypto-ecies v0.0.0-20211207143025-5b84f9efce2b
	github.com/nuts-foundation/go-did v0.5.1
	github.com/nuts-foundation/go-leia/v4 v4.0.3
	github.com/nuts-foundation/go-stoabs v1.9.0
	github.com/piprate/json-gold v0.5.1-0.20230111113000-6ddbe6e6f19f
	github.com/privacybydesign/irmago v0.15.2
	github.com/prometheus/client_golang v1.19.1
	github.com/prometheus/client_model v0.6.1
	github.com/redis/go-redis/v9 v9.5.1
	github.com/shengdoushi/base58 v1.0.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.8.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.9.0
	github.com/twmb/murmur3 v1.1.8
	go.etcd.io/bbolt v1.3.10
	go.uber.org/atomic v1.11.0
	go.uber.org/goleak v1.3.0
	go.uber.org/mock v0.4.0
	golang.org/x/crypto v0.24.0
	golang.org/x/time v0.5.0
	google.golang.org/grpc v1.64.1
	google.golang.org/protobuf v1.34.1
	gopkg.in/Regis24GmbH/go-phonetics.v2 v2.0.3
	gopkg.in/yaml.v3 v3.0.1
	schneider.vip/problem v1.9.1
)

require (
	github.com/BurntSushi/toml v1.3.2 // indirect
	github.com/CloudyKit/fastprinter v0.0.0-20200109182630-33d98a066a53 // indirect
	github.com/CloudyKit/jet/v6 v6.2.0 // indirect
	github.com/Joker/jade v1.1.3 // indirect
	github.com/Shopify/goreferrer v0.0.0-20220729165902-8cddb4f5de06 // indirect
	github.com/alexandrevicenzi/go-sse v1.6.0 // indirect
	github.com/alicebob/gopher-json v0.0.0-20200520072559-a9ecdc9d1d3a // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bwesterb/byteswriter v1.0.0 // indirect
	github.com/bwesterb/go-atum v1.1.5 // indirect
	github.com/bwesterb/go-exptable v1.0.0 // indirect
	github.com/bwesterb/go-pow v1.0.0 // indirect
	github.com/bwesterb/go-xmssmt v1.5.2 // indirect
	github.com/bytedance/sonic v1.10.2 // indirect
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20230717121745-296ad89f973d // indirect
	github.com/chenzhuoyu/iasm v0.9.1 // indirect
	github.com/chromedp/cdproto v0.0.0-20250222051814-50c6cb17f10a // indirect
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/eknkc/basex v1.0.1 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/flosch/pongo2/v4 v4.0.2 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/fxamacker/cbor v1.5.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/gin-gonic/gin v1.9.1 // indirect
	github.com/go-chi/chi/v5 v5.0.12 // indirect
	github.com/go-co-op/gocron v1.28.3 // indirect
	github.com/go-errors/errors v1.4.2 // indirect
	github.com/go-jose/go-jose/v4 v4.0.1 // indirect
	github.com/go-json-experiment/json v0.0.0-20250211171154-1ae217ad3535 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.14.1 // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/go-redsync/redsync/v4 v4.8.2 // indirect
	github.com/go-sql-driver/mysql v1.7.1 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.1 // indirect
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gomarkdown/markdown v0.0.0-20230922105210-14b16010c2ee // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.8 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.6 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/iris-contrib/schema v0.0.6 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgx/v5 v5.5.4 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kataras/blocks v0.0.7 // indirect
	github.com/kataras/golog v0.1.9 // indirect
	github.com/kataras/iris/v12 v12.2.6-0.20230908161203-24ba4e8933b9 // indirect
	github.com/kataras/pio v0.0.12 // indirect
	github.com/kataras/sitemap v0.0.6 // indirect
	github.com/kataras/tunnel v0.0.4 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/mailgun/raymond/v2 v2.0.48 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/microcosm-cc/bluemonday v1.0.25 // indirect
	github.com/microsoft/go-mssqldb v1.6.0 // indirect
	github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1 // indirect
	github.com/minio/highwayhash v1.0.2 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-multihash v0.0.11 // indirect
	github.com/nats-io/jwt/v2 v2.5.7 // indirect
	github.com/nats-io/nkeys v0.4.7 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/nightlyone/lockfile v1.0.0 // indirect
	github.com/nuts-foundation/did-ockam v0.0.0-20230313074753-fafd938c948c // indirect
	github.com/pelletier/go-toml/v2 v2.0.9 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/privacybydesign/gabi v0.0.0-20221212095008-68a086907750 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/schollz/closestmatch v2.1.0+incompatible // indirect
	github.com/sietseringers/go-sse v0.0.0-20200801161811-e2cf2c63ca50 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/tdewolff/minify/v2 v2.12.9 // indirect
	github.com/tdewolff/parse/v2 v2.6.8 // indirect
	github.com/templexxx/cpu v0.1.0 // indirect
	github.com/templexxx/xorsimd v0.4.2 // indirect
	github.com/tidwall/gjson v1.17.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/timshannon/bolthold v0.0.0-20231129192944-dca5178aa629 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/vmihailenco/msgpack/v5 v5.3.5 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/x-cray/logrus-prefixed-formatter v0.5.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yosssi/ace v0.0.5 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	golang.org/x/arch v0.4.0 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/term v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
	gopkg.in/Regis24GmbH/go-diacritics.v2 v2.0.3 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gorm.io/driver/mysql v1.5.2 // indirect
	gorm.io/driver/postgres v1.5.3 // indirect
	gorm.io/driver/sqlserver v1.5.2 // indirect
	gorm.io/gorm v1.25.5 // indirect
	rsc.io/qr v0.2.0 // indirect
)
