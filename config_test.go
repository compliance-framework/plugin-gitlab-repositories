package main

import (
	"testing"
)

func TestPluginConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  PluginConfig
		wantErr bool
	}{
		// auth_type defaults
		{
			name:   "empty auth_type defaults to PAT",
			config: PluginConfig{Token: "tok", Group: "grp"},
		},
		// PAT
		{
			name:   "pat: valid",
			config: PluginConfig{AuthType: AuthTypePAT, Token: "tok", Group: "grp"},
		},
		{
			name:    "pat: missing token",
			config:  PluginConfig{AuthType: AuthTypePAT, Group: "grp"},
			wantErr: true,
		},
		// OAuth
		{
			name:   "oauth: valid",
			config: PluginConfig{AuthType: AuthTypeOAuth, Token: "tok", Group: "grp"},
		},
		{
			name:    "oauth: missing token",
			config:  PluginConfig{AuthType: AuthTypeOAuth, Group: "grp"},
			wantErr: true,
		},
		// client_credentials
		{
			name:   "client_credentials: valid",
			config: PluginConfig{AuthType: AuthTypeClientCredentials, ClientID: "id", ClientSecret: "sec", Scopes: "api", Group: "grp"},
		},
		{
			name:    "client_credentials: missing client_id",
			config:  PluginConfig{AuthType: AuthTypeClientCredentials, ClientSecret: "sec", Scopes: "api", Group: "grp"},
			wantErr: true,
		},
		{
			name:    "client_credentials: missing client_secret",
			config:  PluginConfig{AuthType: AuthTypeClientCredentials, ClientID: "id", Scopes: "api", Group: "grp"},
			wantErr: true,
		},
		{
			name:    "client_credentials: missing scopes",
			config:  PluginConfig{AuthType: AuthTypeClientCredentials, ClientID: "id", ClientSecret: "sec", Group: "grp"},
			wantErr: true,
		},
		// unknown type
		{
			name:    "unknown auth_type",
			config:  PluginConfig{AuthType: "magic", Token: "tok", Group: "grp"},
			wantErr: true,
		},
		// group
		{
			name:    "missing group",
			config:  PluginConfig{Token: "tok"},
			wantErr: true,
		},
		// repository filters
		{
			name:    "included and excluded repos are mutually exclusive",
			config:  PluginConfig{Token: "tok", Group: "grp", IncludedRepositories: "a", ExcludedRepositories: "b"},
			wantErr: true,
		},
		{
			name:   "included repos only is valid",
			config: PluginConfig{Token: "tok", Group: "grp", IncludedRepositories: "a,b"},
		},
		{
			name:   "excluded repos only is valid",
			config: PluginConfig{Token: "tok", Group: "grp", ExcludedRepositories: "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestPluginConfig_ParsePipelineConfig(t *testing.T) {
	t.Parallel()

	t.Run("defaults to 90 when empty", func(t *testing.T) {
		t.Parallel()
		c := &PluginConfig{}
		if err := c.parsePipelineConfig(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.pipelineLookbackDays != 90 {
			t.Errorf("expected 90, got %d", c.pipelineLookbackDays)
		}
	})

	t.Run("parses custom value", func(t *testing.T) {
		t.Parallel()
		c := &PluginConfig{PipelineLookbackDays: "30"}
		if err := c.parsePipelineConfig(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.pipelineLookbackDays != 30 {
			t.Errorf("expected 30, got %d", c.pipelineLookbackDays)
		}
	})

	t.Run("returns error for non-numeric value", func(t *testing.T) {
		t.Parallel()
		c := &PluginConfig{PipelineLookbackDays: "not-a-number"}
		if err := c.parsePipelineConfig(); err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("returns error for zero value", func(t *testing.T) {
		t.Parallel()
		c := &PluginConfig{PipelineLookbackDays: "0"}
		if err := c.parsePipelineConfig(); err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("returns error for negative value", func(t *testing.T) {
		t.Parallel()
		c := &PluginConfig{PipelineLookbackDays: "-7"}
		if err := c.parsePipelineConfig(); err == nil {
			t.Error("expected error, got nil")
		}
	})
}
