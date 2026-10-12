package config

type Config struct {
	Server   ServerConfig   `yaml:"server" json:"server"`
	Auth     AuthConfig     `yaml:"auth" json:"auth"`
	Storage  *StorageConfig `yaml:"storage,omitempty" json:"storage,omitempty"`
	Features FeaturesConfig `yaml:"features" json:"features"`
}

type ServerConfig struct {
	// The name of your server displayed to clients
	Name string `yaml:"name" json:"name"`
	// An optional description of your server displayed to clients
	Description *string `yaml:"description,omitempty" json:"description,omitempty"`
	// The version of the currently supported openapi file
	Version string `yaml:"version" json:"version"`
	// The port the HTTP server will listen on
	Addr string `yaml:"addr" json:"addr"`
	// The file path of your local sqlite database
	DBPath string `yaml:"db_path" json:"db_path"`
	// A 32 bytes encryption key used to encrypt sensitive data using AES-GCM (64 hex characters)
	DBEncryptionKey string `yaml:"db_encryption_key" json:"db_encryption_key"`
}

type AuthConfig struct {
	// The path to the PEM key used to sign JWTs (private key)
	JWTPrivateKeyPath string `yaml:"jwt_private_key_path" json:"jwt_private_key_path"`
	// The path to the PEM key used to verify the signature of JWTs (public key)
	JWTPublicKeyPath string `yaml:"jwt_public_key_path" json:"jwt_public_key_path"`
	// A map mapping OAuth provider ids and their config
	Providers map[string]OAuthAppConfig `yaml:"providers" json:"providers"`
}

type OAuthAppConfig struct {
	// The public client ID of your OAuth app
	ClientID string `yaml:"client_id" json:"client_id"`
	// The secret key of your OAuth app used to exchange the authorization token
	ClientSecret string `yaml:"client_secret" json:"client_secret"`
	// The authorization page url of your OAuth provider
	AuthURL string `yaml:"auth_url" json:"auth_url"`
	// The token endpoint of your OAuth provider
	TokenURL string `yaml:"token_url" json:"token_url"`
	// The OAuth scopes the user will give access too (must give access to email and username)
	Scopes []string `yaml:"scopes" json:"scopes"`
}

type StorageConfig struct {
	// The amount of bytes (base-2) of the free storage quota given to the user
	FreeUserStorageQuota int64     `yaml:"free_user_storage_quota" json:"free_user_storage_quota"`
	Driver               string    `yaml:"driver" json:"driver" jsonschema:"enum=local,enum=s3,default=local"`
	LocalDirectory       string    `yaml:"local_directory,omitempty" json:"local_directory,omitempty"`
	S3Config             *S3Config `yaml:"s3_config,omitempty" json:"s3_config,omitempty"`
}

type S3Config struct {
	Endpoint        string `yaml:"endpoint" json:"endpoint"`
	Bucket          string `yaml:"bucket" json:"bucket"`
	Region          string `yaml:"region" json:"region"`
	AccessKeyID     string `yaml:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key" json:"secret_access_key"`
	ForcePathStyle  bool   `yaml:"force_path_style" json:"force_path_style"`
}

type FeaturesConfig struct {
	Auth         AuthFeatureConfig         `yaml:"core:auth" json:"core:auth"`
	Projects     ProjectsFeatureConfig     `yaml:"core:projects" json:"core:projects"`
	Environments EnvironmentsFeatureConfig `yaml:"core:environments" json:"core:environments"`
	Targets      TargetsFeatureConfig      `yaml:"core:targets" json:"core:targets"`
	Credentials  CredentialsFeatureConfig  `yaml:"core:credentials" json:"core:credentials"`
	Storage      StorageFeatureConfig      `yaml:"core:storage" json:"core:storage"`
	Deployments  DeploymentsFeatureConfig  `yaml:"core:deployments" json:"core:deployments"`
}

type AuthFeatureConfig struct {
	JwtPublicKey string         `yaml:"-" json:"jwtPublicKey" jsonschema:"-"`
	Providers    []AuthProvider `yaml:"providers" json:"providers"`
}

type AuthProvider struct {
	// The ID of the provider used in the AuthConfig
	Id   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
	Kind string `yaml:"kind" json:"kind" jsonschema:"enum=google,enum=apple,enum=microsoft,enum=github,enum=discord,enum=roblox,enum=password,enum=other"`
}

type ProjectsFeatureConfig struct {
	MaxProjectsPerAccount int      `yaml:"maxProjectsPerAccount" json:"maxProjectsPerAccount" jsonschema:"default=10"`
	MinProjectNameLength  int      `yaml:"minProjectNameLength" json:"minProjectNameLength" jsonschema:"default=3"`
	MaxProjectNameLength  int      `yaml:"maxProjectNameLength" json:"maxProjectNameLength" jsonschema:"default=64"`
	SupportedProjectKinds []string `yaml:"supportedProjectKinds" json:"supportedProjectKinds" jsonschema:"enum=game"`
}

type EnvironmentsFeatureConfig struct {
	MaxEnvironmentsPerProject int `yaml:"maxEnvironmentsPerProject" json:"maxEnvironmentsPerProject" jsonschema:"default=5"`
	MinEnvironmentNameLength  int `yaml:"minEnvironmentNameLength" json:"minEnvironmentNameLength" jsonschema:"default=3"`
	MaxEnvironmentNameLength  int `yaml:"maxEnvironmentNameLength" json:"maxEnvironmentNameLength" jsonschema:"default=64"`
	MaxPlacesPerUniverse      int `yaml:"maxPlacesPerUniverse" json:"maxPlacesPerUniverse" jsonschema:"default=20"`
}

type TargetsFeatureConfig struct {
	MaxTargetsPerProject int      `yaml:"maxTargetsPerProject" json:"maxTargetsPerProject" jsonschema:"default=150"`
	MinTargetNameLength  int      `yaml:"minTargetNameLength" json:"minTargetNameLength" jsonschema:"default=1"`
	MaxTargetNameLength  int      `yaml:"maxTargetNameLength" json:"maxTargetNameLength" jsonschema:"default=64"`
	SupportedTargetKinds []string `yaml:"supportedTargetKinds" json:"supportedTargetKinds" jsonschema:"enum=place"`
}

type CredentialsFeatureConfig struct {
	MaxCredentialsPerProject int      `yaml:"maxCredentialsPerProject" json:"maxCredentialsPerProject" jsonschema:"default=5"`
	MinCredentialNameLength  int      `yaml:"minCredentialNameLength" json:"minCredentialNameLength" jsonschema:"default=3"`
	MaxCredentialNameLength  int      `yaml:"maxCredentialNameLength" json:"maxCredentialNameLength" jsonschema:"default=64"`
	SupportedCredentialKinds []string `yaml:"supportedCredentialKinds" json:"supportedCredentialKinds" jsonschema:"enum=api-key"`
}

type StorageFeatureConfig struct {
	MaxStorageObjectsPerAccount int      `yaml:"maxStorageObjectsPerAccount" json:"maxStorageObjectsPerAccount" jsonschema:"default=3"`
	MinStorageNameLength        int      `yaml:"minStorageNameLength" json:"minStorageNameLength" jsonschema:"default=3"`
	MaxStorageNameLength        int      `yaml:"maxStorageNameLength" json:"maxStorageNameLength" jsonschema:"default=64"`
	SupportedStorageKinds       []string `yaml:"supportedStorageKinds" json:"supportedStorageKinds" jsonschema:"enum=S3,enum=internal"`
}

type DeploymentsFeatureConfig struct {
	MaxDeploymentsPerProject int `yaml:"maxDeploymentsPerProject" json:"maxDeploymentsPerProject" jsonschema:"default=50"`
	MaxPlacesPerDeployment   int `yaml:"maxPlacesPerDeployment" json:"maxPlacesPerDeployment" jsonschema:"default=10"`
	MinVersionLength         int `yaml:"minVersionLength" json:"minVersionLength" jsonschema:"default=1"`
	MaxVersionLength         int `yaml:"maxVersionLength" json:"maxVersionLength" jsonschema:"default=64"`
	MaxPlaceFileSizeBytes    int `yaml:"maxPlaceFileSizeBytes" json:"maxPlaceFileSizeBytes" jsonschema:"default=5368709120"`
}
