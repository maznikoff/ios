// Package keychain loads the device keychain from an encrypted backup.
package keychain

// Most of this is derived from cmd/irestore

import (
	"encoding/binary"
	"time"

	"bytes"
	"fmt"

	"crypto/aes"
	"crypto/sha1"

	"github.com/dunhamsteve/plist"
	"github.com/maznikoff/ios/backup"
	"github.com/maznikoff/ios/crypto/aeswrap"
	"github.com/maznikoff/ios/crypto/gcm"
	"github.com/maznikoff/ios/encoding/asn1"
)

const (
	keychainId = "KeychainDomain-keychain-backup.plist"
	KService   = "svce"
	KData      = "v_Data"
)

var (
	keychainIdHash = fmt.Sprintf("%0x", sha1.Sum([]byte(keychainId)))
)

type kcEntry struct {
	Data []byte `plist:"v_Data"`
	Ref  []byte `plist:"v_PersistentRef"`
}

type rawKeychain struct {
	Internet []kcEntry `plist:"inet"`
	General  []kcEntry `plist:"genp"`
	Certs    []kcEntry `plist:"cert"`
	Keys     []kcEntry `plist:"keys"`
}

var le = binary.LittleEndian

// Mostly works, but I don't think time is getting populated.
type entry struct {
	Raw   asn1.RawContent
	Key   string
	Value interface{}
}

type dateEntry struct {
	Key  string
	Time time.Time
}

type entrySET []entry

func parseRecord(data []byte) (map[string]interface{}, error) {
	var v entrySET
	rval := make(map[string]interface{})
	_, err := asn1.Unmarshal(data, &v)
	if err != nil {
		return nil, err
	}
	for _, entry := range v {
		// Time values come through as nil, so we try again with a "dateEntry" structure.
		if entry.Value == nil {
			var entry2 dateEntry
			_, err := asn1.Unmarshal(entry.Raw, &entry2)
			if err == nil {
				entry.Value = entry2.Time
			}
		}

		rval[entry.Key] = entry.Value
	}
	return rval, nil
}

func dumpKeyGroup(db *backup.MobileBackup, group []kcEntry) (kg KeychainGroup, err error) {
	var rval KeychainGroup
	for _, key := range group {
		version := le.Uint32(key.Data)
		class := le.Uint32(key.Data[4:])
		switch version {
		case 3:
			l := le.Uint32(key.Data[8:])
			wkey := key.Data[12 : 12+l]
			edata := key.Data[12+l:]

			// Find key for class
			ckey := db.Keybag.GetClassKey(class)
			if ckey == nil {
				continue
			}

			key := aeswrap.Unwrap(ckey, wkey)
			if key == nil {
				continue
			}
			// Create a gcm cipher
			c, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			gcm, err := gcm.NewGCM(c)
			if err != nil {
				return nil, err
			}
			plain, err := gcm.Open(nil, nil, edata, nil)
			if err != nil {
				return nil, err
			}
			record, err := parseRecord(plain)
			if err != nil {
				return kg, fmt.Errorf("failed to parse record: %v", err)
			}
			rval = append(rval, record)
		default:
			return kg, fmt.Errorf("Unhandled keychain blob version %d", version)
		}
	}

	return rval, nil
}

// Keychain holds a decrypted keychain
type Keychain struct {
	General  KeychainGroup
	Internet KeychainGroup
	Certs    KeychainGroup
	Keys     KeychainGroup
}

// KeychainGroup holds a  group of keychain items
type KeychainGroup []interface{}

// FindByKeyMatch queries for matching entries in a group.
//
// eg. FindByKeyMatch(keychain.KService, "ParentalControls")
func (kg KeychainGroup) FindByKeyMatch(key, value string) (items []KeychainItem) {
	for _, gv := range kg {
		item, ok := gv.(map[string]interface{})
		if !ok {
			continue
		}
		if item[key] == value {
			items = append(items, KeychainItem(item))
		}
	}
	return items
}

// KeychainItem represents a single keychain entry.
type KeychainItem map[string]interface{}

// Load decrypts the keychain from an encrypted backup.
func Load(db *backup.MobileBackup) (*Keychain, error) {
	var kc Keychain
	var raw rawKeychain
	rec := db.RecordById(keychainIdHash)
	if rec == nil {
		return nil, fmt.Errorf("Keychain record not found")
	}
	data, err := db.ReadFile(*rec)
	if err != nil {
		return nil, err
	}

	if err := plist.Unmarshal(bytes.NewReader(data), &raw); err != nil {
		return nil, fmt.Errorf("failed to decode keychain plist data: %v", err)
	}

	if kc.General, err = dumpKeyGroup(db, raw.General); err != nil {
		return nil, fmt.Errorf("failed to decode general group: %v", err)
	}
	if kc.Internet, err = dumpKeyGroup(db, raw.Internet); err != nil {
		return nil, fmt.Errorf("failed to decode internet group: %v", err)
	}
	if kc.Certs, err = dumpKeyGroup(db, raw.Certs); err != nil {
		return nil, fmt.Errorf("failed to decode certs group: %v", err)
	}
	if kc.Keys, err = dumpKeyGroup(db, raw.Keys); err != nil {
		return nil, fmt.Errorf("failed to decode keys group: %v", err)
	}

	return &kc, nil
}
