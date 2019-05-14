package main

import (
	"encoding/binary"
	"encoding/json"
	"time"
	"text/tabwriter"
	"strconv"

	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"flag"
	"path"
	"path/filepath"
	"strings"

	"crypto/aes"

	"github.com/maznikoff/ios/backup"
	"github.com/maznikoff/ios/crypto/aeswrap"
	"github.com/maznikoff/ios/crypto/gcm"
	"github.com/maznikoff/ios/encoding/asn1"
	"github.com/dunhamsteve/plist"
	"golang.org/x/crypto/ssh/terminal"
)

// Quick and Dirty error handling - when I don't expect an error, but want to know if it happens
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func dumpJSON(x interface{}) {
	json, err := json.MarshalIndent(x, "", "  ")
	must(err)
	fmt.Println(string(json))
}

func getpass() string {
	fmt.Fprint(os.Stderr, "Backup Password: ")
	pw, err := terminal.ReadPassword(0)
	must(err)
	fmt.Println()
	return string(pw)
}

func domains(db *backup.MobileBackup) {
	for _, domain := range db.Domains() {
		fmt.Println(domain)
	}
}
func apps(db *backup.MobileBackup) {
	for app := range db.Manifest.Applications {
		fmt.Println(app)
	}
}

func list(db *backup.MobileBackup, domain string) {
	for _, rec := range db.Records {
		// just files for now
		if rec.Length > 0 {
			if domain == "*" {
				fmt.Println(rec.Domain, rec.Path)
			} else if domain == rec.Domain {
				fmt.Println(rec.Path)
			}
		}
	}
}

type KCEntry struct {
	Data []byte `plist:"v_Data"`
	Ref  []byte `plist:"v_PersistentRef"`
}

type Keychain struct {
	Internet []KCEntry `plist:"inet"`
	General  []KCEntry `plist:"genp"`
	Certs    []KCEntry `plist:"cert"`
	Keys     []KCEntry `plist:"keys"`
}

var le = binary.LittleEndian

// Mostly works, but I don't think time is getting populated.
type Entry struct {
	Raw   asn1.RawContent
	Key   string
	Value interface{}
}

type DateEntry struct {
	Key  string
	Time time.Time
}

type EntrySET []Entry

func parseRecord(data []byte) map[string]interface{} {
	var v EntrySET
	rval := make(map[string]interface{})
	_, err := asn1.Unmarshal(data, &v)
	if err != nil {
		fmt.Println(err)
		ioutil.WriteFile("failed.bin", data, 0644)
	}
	// must(err)
	for _, entry := range v {
		// Time values come through as nil, so we try again with a "DateEntry" structure.
		if entry.Value == nil {
			var entry2 DateEntry
			_, err := asn1.Unmarshal(entry.Raw, &entry2)
			if err == nil {
				entry.Value = entry2.Time
			}
		}

		rval[entry.Key] = entry.Value
	}
	return rval
}

func dumpKeyGroup(db *backup.MobileBackup, group []KCEntry) []interface{} {
	var rval []interface{}
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
				fmt.Println("No key for class", class, string(key.Ref)[:4], key.Ref[4:])
				continue
			}

			key := aeswrap.Unwrap(ckey, wkey)
			if key == nil {
				fmt.Println("unwrap failed for class", class)
				continue
			}
			// Create a gcm cipher
			c, err := aes.NewCipher(key)
			if err != nil {
				log.Panic(err)
			}
			gcm, err := gcm.NewGCM(c)
			if err != nil {
				log.Panic(err)
			}
			plain, err := gcm.Open(nil, nil, edata, nil)
			must(err)
			record := parseRecord(plain)
			rval = append(rval, record)
		default:
			panic(fmt.Sprintf("Unhandled keychain blob version %d", version))
		}
	}

	return rval
}

func dumpkeys(db *backup.MobileBackup, outfile string) {
	for _, rec := range db.Records {
		if rec.Domain == "KeychainDomain" && rec.Path == "keychain-backup.plist" {
			fmt.Println(rec)
			data, err := db.ReadFile(rec)
			must(err)
			ioutil.WriteFile("kcb.plist", data, 0x644)

			fmt.Println("read", len(data))
			var v Keychain
			err = plist.Unmarshal(bytes.NewReader(data), &v)
			must(err)

			dump := make(map[string][]interface{})
			dump["General"] = dumpKeyGroup(db, v.General)
			dump["Internet"] = dumpKeyGroup(db, v.Internet)
			dump["Certs"] = dumpKeyGroup(db, v.Certs)
			dump["Keys"] = dumpKeyGroup(db, v.Keys)
			s, err := json.MarshalIndent(dump, "", "  ")
			must(err)
			if outfile != "" {
				err = ioutil.WriteFile(outfile, s, 0644)
				must(err)
			} else {
				_, err = os.Stdout.Write(s)
				must(err)
			}
		}
	}
}

func restore(db *backup.MobileBackup, domain string, dest string) {
	var err error
	var total int64
	for _, rec := range db.Records {
		if rec.Length > 0 {
			var outPath string
			if domain == "*" {
				outPath = path.Join(dest, rec.Domain, rec.Path)
			} else if rec.Domain == domain {
				outPath = path.Join(dest, rec.Path)
			}

			if outPath != "" {
				fmt.Println(rec.Path)

				dir := path.Dir(outPath)
				err = os.MkdirAll(dir, 0755)
				must(err)
				r, err := db.FileReader(rec)
				if err != nil {
					log.Println("error reading file", rec, err)
					continue
				}
				must(err)
				w, err := os.Create(outPath)
				must(err)
				n, err := io.Copy(w, r)
				total += n
				r.Close()
				w.Close()
			}
		}
	}
	fmt.Println("Wrote", total, "bytes")
}

// exists returns whether the given file or directory exists or not
func exists(path string) (bool) {
    _, err := os.Stat(path)
    if err == nil { return true }
    if os.IsNotExist(err) { return false }
    return true
}

func main() {
	pathToBackupsPtr := flag.String("path", path.Join(os.Getenv("HOME"), "Library/Application Support/MobileSync/Backup"), "path to dir where backups are stored")
	flag.Parse()

	mm, err := backup.Enumerate(*pathToBackupsPtr)
	must(err)

	var selected *backup.Backup

	// component without flag is udid
	if len(flag.Args()) >= 1 {
		key := flag.Args()[0]
		for _, man := range mm {
			dashed := strings.Contains(man.FileName, "-")
			if man.DeviceName == key && !dashed {
				selected = &man
				break
			}
			if man.FileName == key {
				selected = &man
				break
			}
			if strings.Contains(man.DeviceName, key) && !dashed {
				selected = &man
				break
			}
			if strings.Contains(man.FileName, key) && !dashed {
				selected = &man
				break
			}
		}
	}

	if selected == nil {
		w:= new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 8, 2, '\t', 0)
		fmt.Fprintln(w, "Device Name\tFile Name\tDate\tVersion\tDevice\tEncrypted")
		fmt.Fprintln(w, "===========\t=========\t====\t=======\t======\t=========")
		for _, man := range mm {
			fmt.Fprintln(w, man.DeviceName +
					"\t" + man.FileName +
					"\t" + man.Date.String() +
					"\t" + man.Version +
					"\t" + man.Device +
					"\t" + strconv.FormatBool(man.Encrypted))
		}
		w.Flush()
		return
	}
	fmt.Println("Selected", selected.DeviceName, selected.FileName)

	db, err := backup.Open(*pathToBackupsPtr, selected.FileName)
	must(err)

	if db.Manifest.IsEncrypted {
		err = db.SetPassword(getpass())
		must(err)
	}
	must(db.Load())
	if len(flag.Args()) < 2 {
		for _, domain := range db.Domains() {
			fmt.Println(domain)
		}
		return
	}

	name := filepath.Base(os.Args[0])

	help := func() {
		fmt.Printf(`Usage:
    %v [-path PATH] deviceID/deviceName ls [domain]
    %v [-path PATH] deviceID/deviceName restore domain dest
    %v [-path PATH] deviceID/deviceName dumpkeys [outputfile]
    %v [-path PATH] deviceID/deviceName apps
`, name, name, name, name)
	}

	var cmd string
	if len(flag.Args()) > 1 {
		cmd = flag.Args()[1]
	}
	switch cmd {
	case "ls", "list":
		if len(flag.Args()) > 2 {
			list(db, flag.Args()[2])
		} else {
			domains(db)
		}
	case "restore":
		if len(flag.Args()) > 3 {
			restore(db, flag.Args()[2], flag.Args()[3])
		} else {
			help()
		}
	case "apps":
		apps(db)
	case "dumpkeys":
		var out string
		if len(flag.Args()) > 2 {
			out = flag.Args()[2]
		}
		dumpkeys(db, out)
	default:
		help()
	}
}
