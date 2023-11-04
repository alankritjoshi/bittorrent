package main

import (
	// Uncomment this line to pass the first stage

	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/codecrafters-io/bittorrent-starter-go/bencode"
	"github.com/codecrafters-io/bittorrent-starter-go/torrent"
	// bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

func main() {
	command := os.Args[1]

	switch command {
	case "decode":
		bencodedValue := os.Args[2]

		decoded, err := bencode.Decode(bencodedValue)
		if err != nil {
			log.Fatalf("Decode bencode ran into an error %s: %v", bencodedValue, err)
		}

		jsonOutput, _ := json.Marshal(decoded)
		fmt.Println(string(jsonOutput))
	case "info":
		torrentFile := os.Args[2]

		file, err := os.Open(torrentFile)
		if err != nil {
			log.Fatalf("Unable to open torrent file %s: %v", torrentFile, err)
		}

		bytes, err := io.ReadAll(file)
		if err != nil {
			log.Fatalf("Unable to read torrent file %s: %v", torrentFile, err)
		}

		content := string(bytes)

		decoded, err := bencode.Decode(content)
		if err != nil {
			log.Fatalf("Decode bencode ran into an error %s: %v", content, err)
		}

		torrent, err := torrent.MapToMetaInfo((*decoded).(map[string]interface{}))
		if err != nil {
			log.Fatalf("Unable to deserialize torrent map into Torrent struct %s: %v", *decoded, err)
		}

		encodedTorrentInfo, err := bencode.Encode((*decoded).(map[string]interface{})["info"])
		if err != nil {
			log.Fatalf("Unable to encode torrent info %v: %v", torrent.Info, err)
		}

		infoHash := sha1.New()

		_, err = infoHash.Write([]byte(encodedTorrentInfo))
		if err != nil {
			log.Fatalf("Unable to hash torrent info %s: %v", encodedTorrentInfo, err)
		}

		fmt.Printf("Tracker URL: %s\n", torrent.Announce)
		fmt.Printf("Length: %d\n", torrent.Info.Length)
		fmt.Printf("Info Hash: %x", infoHash.Sum(nil))
	default:
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
