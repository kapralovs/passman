package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"

	original := &Config{
		SessionDuration: 30 * time.Minute,
		Key:             "0102030405060708091011121314151617181920212223242526272829303132",
	}

	err := Save(path, original)
	assert.NoError(t, err)

	loaded, err := Load(path)
	assert.NoError(t, err)

	assert.Equal(t, original.SessionDuration, loaded.SessionDuration)
	assert.Equal(t, original.Key, loaded.Key)
}

func TestConfig_LoadNonExistent(t *testing.T) {
	_, err := Load("/nonexistent/path/config.json")
	assert.Error(t, err)
}

func TestConfig_LoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"

	err := os.WriteFile(path, []byte("not json"), 0600)
	assert.NoError(t, err)

	_, err = Load(path)
	assert.Error(t, err)
}
