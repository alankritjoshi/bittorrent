package main

import (
	// Uncomment this line to pass the first stage

	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	// bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

type metaInfo struct {
	announce  string
	createdBy string
	info      info
}

type info struct {
	hash        string
	length      int
	name        string
	pieceLength int
	pieces      []string
}

func (i *info) getDecodedInfoHash() (string, error) {
	infoHashBytes, err := hex.DecodeString(i.hash)
	if err != nil {
		return "", fmt.Errorf("Unable to decode hex info hash %s: %v", i.hash, err)
	}

	return string(infoHashBytes), nil
}

func deserializeMetaInfo(m map[string]interface{}) (*metaInfo, error) {
	var t metaInfo
	var ok bool

	if t.announce, ok = m["announce"].(string); !ok {
		return nil, fmt.Errorf("Invalid or missing 'announce'")
	}

	infoMap, ok := m["info"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Invalid or missing 'info'")
	}

	var info info

	encodedInfo, err := encode(m["info"])
	if err != nil {
		return nil, fmt.Errorf("Unable to encode torrent info %v: %v", m, err)
	}

	infoHash := sha1.New()

	_, err = infoHash.Write([]byte(encodedInfo))
	if err != nil {
		return nil, fmt.Errorf("Unable to hash torrent info %s: %v", encodedInfo, err)
	}

	info.hash = hex.EncodeToString(infoHash.Sum(nil))

	if info.length, ok = infoMap["length"].(int); !ok {
		return nil, fmt.Errorf("Invalid or missing 'length'")
	}

	if info.name, ok = infoMap["name"].(string); !ok {
		return nil, fmt.Errorf("Invalid or missing 'name'")
	}

	if info.pieceLength, ok = infoMap["piece length"].(int); !ok {
		return nil, fmt.Errorf("Invalid or missing 'pieceLength'")
	}

	if piecesBytesString, ok := infoMap["pieces"].(string); ok {
		piecesBytes := []byte(piecesBytesString)
		var pieceHashes []string
		for i := 0; i < len(piecesBytes); i += 20 {
			piece := piecesBytes[i : i+20]
			pieceHashes = append(pieceHashes, hex.EncodeToString(piece))
		}
		info.pieces = pieceHashes
	} else {
		return nil, fmt.Errorf("Invalid or missing 'pieces'")
	}

	t.info = info

	return &t, nil
}

func encode(data interface{}) (string, error) {
	switch v := data.(type) {
	case int:
		return fmt.Sprintf("i%de", v), nil
	case string:
		return fmt.Sprintf("%d:%s", len(v), v), nil
	case []interface{}:
		var builder strings.Builder
		for index, item := range v {
			encodedItem, err := encode(item)
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

			encodedKey, err := encode(key)
			if err != nil {
				return "", fmt.Errorf("Unable to encode key %s in map %v: %v", key, v, err)
			}

			builder.WriteString(encodedKey)

			encodedValue, err := encode(value)
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

type trackerResponse struct {
	interval int
	peers    []string
}

func deserializeTrackerResponse(m map[string]interface{}) (*trackerResponse, error) {
	var t trackerResponse
	var ok bool

	if t.interval, ok = m["interval"].(int); !ok {
		return nil, fmt.Errorf("Invalid or missing 'interval'")
	}

	if t.peers, ok = m["peers"].([]string); !ok {
		return nil, fmt.Errorf("Invalid or missing 'peers'")
	}

	return &t, nil
}

func GetTrackerInfo(m *metaInfo) (*trackerResponse, error) {
	baseUrl, err := url.Parse(m.announce)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse tracker url %s: %v", m.announce, err)
	}

	query := baseUrl.Query()

	decodedInfoHash, err := m.info.getDecodedInfoHash()
	if err != nil {
		return nil, fmt.Errorf("Unable to get decoded info hash %s: %v", m.info.hash, err)
	}

	params := map[string]string{
		"info_hash":  url.QueryEscape(decodedInfoHash),
		"peer_id":    "00112233445566778899",
		"port":       "6881",
		"uploaded":   "0",
		"downloaded": "0",
		"left":       strconv.Itoa(m.info.length),
		"compact":    "1",
	}

	for key, value := range params {
		query.Set(key, value)
	}

	baseUrl.RawQuery = query.Encode()

	resp, err := http.Get(baseUrl.String())
	if err != nil {
		return nil, fmt.Errorf("Unable to get tracker info from url %s: %v", baseUrl.String(), err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Unable to read tracker response body: %v", err)
	}

	decoded, err := Decode(string(body))
	if err != nil {
		return nil, fmt.Errorf("Unable to decode tracker response body %s: %v", string(body), err)
	}

	trackerResponse, err := deserializeTrackerResponse((*decoded).(map[string]interface{}))
	if err != nil {
		return nil, fmt.Errorf("Unable to deserialize tracker response %s: %v", *decoded, err)
	}

	return trackerResponse, nil
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
		torrent, err := getMetaInfo(os.Args[2])
		if err != nil {
			log.Fatalf("Unable to get meta info for file name %s: %v", os.Args[2], err)
		}

		fmt.Printf("Tracker URL: %s\n", torrent.announce)
		fmt.Printf("Length: %d\n", torrent.info.length)
		fmt.Printf("Info Hash: %s\n", torrent.info.hash)
		fmt.Printf("Piece Length: %d\n", torrent.info.pieceLength)
		fmt.Printf("Piece Hashes:\n")
		for _, piece := range torrent.info.pieces {
			fmt.Printf("%s\n", piece)
		}
	case "peers":
		torrent, err := getMetaInfo(os.Args[2])
		if err != nil {
			log.Fatalf("Unable to get meta info for file name %s: %v", os.Args[2], err)
		}

		trackerResponse, err := GetTrackerInfo(torrent)
		if err != nil {
			log.Fatalf("Unable to get tracker info for torrent %v: %v", torrent, err)
		}

		for _, peer := range trackerResponse.peers {
			fmt.Printf("%s\n", peer)
		}
	default:
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}

func getMetaInfo(torrentFile string) (*metaInfo, error) {
	if torrentFile == "" {
		return nil, fmt.Errorf("Missing torrent file")
	}

	file, err := os.Open(torrentFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to open torrent file %s: %v", torrentFile, err)
	}

	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("Unable to read torrent file %s: %v", torrentFile, err)
	}

	decoded, err := Decode(string(bytes))
	if err != nil {
		return nil, fmt.Errorf("Decode bencode ran into an error %s: %v", string(bytes), err)
	}

	torrent, err := deserializeMetaInfo((*decoded).(map[string]interface{}))
	if err != nil {
		return nil, fmt.Errorf("Unable to deserialize metainfo %s: %v", *decoded, err)
	}

	return torrent, nil
}
