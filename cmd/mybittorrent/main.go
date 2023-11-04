package main

import (
	// Uncomment this line to pass the first stage

	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	// bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

type MetaInfo struct {
	Announce  string
	CreatedBy string
	Info      Info
}

type Info struct {
	Length      int
	Name        string
	PieceLength int
	Pieces      []string
}

func MapToMetaInfo(m map[string]interface{}) (*MetaInfo, error) {
	var t MetaInfo
	var ok bool

	if t.Announce, ok = m["announce"].(string); !ok {
		return nil, fmt.Errorf("Invalid or missing 'announce'")
	}

	infoMap, ok := m["info"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Invalid or missing 'info'")
	}

	var info Info
	if info.Length, ok = infoMap["length"].(int); !ok {
		return nil, fmt.Errorf("Invalid or missing 'length'")
	}
	if info.Name, ok = infoMap["name"].(string); !ok {
		return nil, fmt.Errorf("Invalid or missing 'name'")
	}
	if info.PieceLength, ok = infoMap["piece length"].(int); !ok {
		return nil, fmt.Errorf("Invalid or missing 'pieceLength'")
	}
	if piecesBytesString, ok := infoMap["pieces"].(string); ok {
		piecesBytes := []byte(piecesBytesString)
		var pieceHashes []string
		for i := 0; i < len(piecesBytes); i += 20 {
			var pieceHashBuilder strings.Builder
			for _, b := range piecesBytes[i : i+20] {
				pieceHash := fmt.Sprintf("%02x", uint8(b))
				pieceHashBuilder.Write([]byte(pieceHash))
			}

			pieceHashes = append(pieceHashes, pieceHashBuilder.String())
		}
		info.Pieces = pieceHashes
	} else {
		return nil, fmt.Errorf("Invalid or missing 'pieces'")
	}

	t.Info = info

	return &t, nil
}

func Encode(data interface{}) (string, error) {
	switch v := data.(type) {
	case int:
		return fmt.Sprintf("i%de", v), nil
	case string:
		return fmt.Sprintf("%d:%s", len(v), v), nil
	case []interface{}:
		var builder strings.Builder
		for index, item := range v {
			encodedItem, err := Encode(item)
			if err != nil {
				return "", fmt.Errorf("Unable to encode item %s at index %d in list %v: %w", item, index, v, err)
			}
			builder.WriteString(encodedItem)
		}
		return fmt.Sprintf("l%se", builder.String()), nil
	case map[string]interface{}:
		var builder strings.Builder

		sortedKeys := make([]string, 0, len(v))
		for k := range v {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)

		for _, key := range sortedKeys {
			value := v[key]

			encodedKey, err := Encode(key)
			if err != nil {
				return "", fmt.Errorf("Unable to encode key %s in map %v: %v", key, v, err)
			}

			builder.WriteString(encodedKey)

			encodedValue, err := Encode(value)
			if err != nil {
				return "", fmt.Errorf("Unable to encode value %s for key %s in map %v: %w", value, key, v, err)
			}

			builder.WriteString(encodedValue)
		}
		return fmt.Sprintf("d%se", builder.String()), nil
	default:
		return "", fmt.Errorf("Unknown bencode type: %v", v)
	}
}

func decode(bencodedString string) (interface{}, string, error) {
	firstChar := bencodedString[0]

	switch {
	case firstChar == 'i':
		firstEnd := strings.Index(bencodedString, "e")
		if firstEnd == -1 {
			return "", "", fmt.Errorf("Invalid bencode integer %s", bencodedString)
		}

		integer, err := strconv.Atoi(bencodedString[1:firstEnd])
		if err != nil {
			return "", "", fmt.Errorf("Invalid bencode integer %s: %w", bencodedString, err)
		}

		return integer, bencodedString[firstEnd+1:], nil
	case unicode.IsDigit(rune(firstChar)):
		firstColonIndex := strings.Index(bencodedString, ":")

		lengthStr := bencodedString[:firstColonIndex]

		length, err := strconv.Atoi(lengthStr)
		if err != nil {
			return "", "", fmt.Errorf("Invalid bencode string %s: %w", bencodedString, err)
		}

		return bencodedString[firstColonIndex+1 : firstColonIndex+1+length], bencodedString[firstColonIndex+1+length:], nil
	case firstChar == 'l':
		var (
			list       []interface{} = make([]interface{}, 0)
			remaining  string        = bencodedString[1:]
			to_process string
		)

		for {
			var (
				listItem interface{}
				err      error
			)

			to_process = remaining

			// 'e' is found
			if remaining[0] == 'e' {
				// remove this 'e' from remaining when returning list
				remaining = remaining[1:]
				break
			}

			// if 'e' is not found, then there should be remaining text
			if len(remaining) == 0 {
				return "", "", fmt.Errorf("Invalid bencode list termination %s", bencodedString)
			}

			listItem, remaining, err = decode(to_process)
			if err != nil {
				return "", "", fmt.Errorf("Invalid bencode list %s: %w", bencodedString, err)
			}

			list = append(list, listItem)
		}

		return list, remaining, nil
	case firstChar == 'd':
		var (
			dictionary  map[string]interface{} = make(map[string]interface{}, 0)
			remaining   string                 = bencodedString[1:]
			to_process  string
			current_key string
			index       int
		)

		for {
			var (
				dictionaryItem interface{}
				err            error
			)

			to_process = remaining

			// 'e' is found
			if remaining[0] == 'e' {
				// remove this 'e' from remaining when returning dictionary
				remaining = remaining[1:]
				break
			}

			// if 'e' is not found, then there should be remaining text
			if len(remaining) == 0 {
				return "", "", fmt.Errorf("Invalid bencode dictionary termination %s", bencodedString)
			}

			dictionaryItem, remaining, err = decode(to_process)
			if err != nil {
				return "", "", fmt.Errorf("Invalid bencode dictionary %s: %w", bencodedString, err)
			}

			if index%2 == 0 {
				current_key = dictionaryItem.(string)
			} else {
				dictionary[current_key] = dictionaryItem
			}

			index++
		}

		return dictionary, remaining, nil
	default:
		return "", "", fmt.Errorf("Unknown bencode type: %s", bencodedString)
	}
}

// Example:
// - 5:hello -> hello
// - 10:hello12345 -> hello12345
func Decode(bencodedString string) (*interface{}, error) {
	decoded, remaining, err := decode(bencodedString)
	if err != nil {
		return nil, err
	}

	if len(remaining) != 0 {
		return nil, fmt.Errorf("Found remaining text after decoding bencode %s: %s", bencodedString, remaining)
	}

	return &decoded, nil
}

func getSha1Hash(encodedTorrentInfo string) (string, error) {
	infoHash := sha1.New()

	_, err := infoHash.Write([]byte(encodedTorrentInfo))
	if err != nil {
		return "", fmt.Errorf("Unable to hash torrent info %s: %v", encodedTorrentInfo, err)
	}

	return fmt.Sprintf("%x", infoHash.Sum(nil)), nil
}

func main() {
	command := os.Args[1]

	switch command {
	case "decode":
		bencodedValue := os.Args[2]

		decoded, err := Decode(bencodedValue)
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

		decoded, err := Decode(content)
		if err != nil {
			log.Fatalf("Decode bencode ran into an error %s: %v", content, err)
		}

		torrent, err := MapToMetaInfo((*decoded).(map[string]interface{}))
		if err != nil {
			log.Fatalf("Unable to deserialize torrent map into Torrent struct %s: %v", *decoded, err)
		}

		encodedTorrentInfo, err := Encode((*decoded).(map[string]interface{})["info"])
		if err != nil {
			log.Fatalf("Unable to encode torrent info %v: %v", torrent.Info, err)
		}

		infoHash, err := getSha1Hash(encodedTorrentInfo)
		if err != nil {
			log.Fatalf("Unable to get info hash for torrent info %s: %v", encodedTorrentInfo, err)
		}

		pieceHashes := make([]string, 0, len(torrent.Info.Pieces))
		for index, piece := range torrent.Info.Pieces {
			pieceHash, err := getSha1Hash(string(piece[:]))
			if err != nil {
				log.Fatalf("Unable to get piece hash for piece #%d with value %s: %v", index, piece, err)
			}

			pieceHashes = append(pieceHashes, pieceHash)
		}

		fmt.Printf("Tracker URL: %s\n", torrent.Announce)
		fmt.Printf("Piece Length: %d\n", torrent.Info.Length)
		fmt.Printf("Info Hash: %s\n", infoHash)
		fmt.Printf("Piece Hashes:\n")
		for index, pieceHash := range pieceHashes {
			if index == len(pieceHashes) {
				fmt.Printf("%s", pieceHash)
			} else {
				fmt.Printf("%s\n", pieceHash)
			}
		}
	default:
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
