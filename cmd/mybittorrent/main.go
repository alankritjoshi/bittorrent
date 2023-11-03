package main

import (
	// Uncomment this line to pass the first stage

	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"unicode"
	// bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

type Torrent struct {
	Announce  string
	CreatedBy string
	Info      Info
}

type Info struct {
	Length      int
	Name        string
	PieceLength int
	Pieces      string
}

func mapToTorrent(m map[string]interface{}) (Torrent, error) {
	var t Torrent
	var ok bool

	if t.Announce, ok = m["announce"].(string); !ok {
		return t, fmt.Errorf("Invalid or missing 'announce'")
	}

	infoMap, ok := m["info"].(map[string]interface{})
	if !ok {
		return t, fmt.Errorf("Invalid or missing 'info'")
	}

	var info Info
	if info.Length, ok = infoMap["length"].(int); !ok {
		return t, fmt.Errorf("Invalid or missing 'length'")
	}
	if info.Name, ok = infoMap["name"].(string); !ok {
		return t, fmt.Errorf("Invalid or missing 'name'")
	}
	if info.PieceLength, ok = infoMap["pieceLength"].(int); !ok {
		return t, fmt.Errorf("Invalid or missing 'pieceLength'")
	}
	if pieces, ok := infoMap["pieces"].(string); ok {
		info.Pieces = pieces
	} else {
		return t, fmt.Errorf("Invalid or missing 'pieces'")
	}

	t.Info = info

	return t, nil
}

// Example:
// - 5:hello -> hello
// - 10:hello12345 -> hello12345
func decodeBencode(bencodedString string) (interface{}, string, error) {
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

			listItem, remaining, err = decodeBencode(to_process)
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

			dictionaryItem, remaining, err = decodeBencode(to_process)
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

func main() {
	command := os.Args[1]

	if command == "decode" {
		bencodedValue := os.Args[2]

		decoded, remaining, err := decodeBencode(bencodedValue)
		if err != nil {
			log.Fatalf("Decode bencode ran into an error %s: %v", bencodedValue, err)
		}

		if len(remaining) != 0 {
			log.Fatalf("Found remaining text after decoding bencode %s", bencodedValue)
		}

		jsonOutput, _ := json.Marshal(decoded)
		fmt.Println(string(jsonOutput))
	} else if command == "info" {
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

		decoded, remaining, err := decodeBencode(content)
		if err != nil {
			log.Fatalf("Decode bencode ran into an error %s: %v", content, err)
		}

		if len(remaining) != 0 {
			log.Fatalf("Found remaining text after decoding bencode %s", content)
		}

		torrent, err := mapToTorrent(decoded.(map[string]interface{}))
		if err != nil {
			log.Fatalf("Unable to deserialize torrent map into Torrent struct %s: %v", decoded, err)
		}

		fmt.Printf("Tracker URL: %s\n", torrent.Announce)
		fmt.Printf("Length: %d", torrent.Info.Length)
	} else {
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
