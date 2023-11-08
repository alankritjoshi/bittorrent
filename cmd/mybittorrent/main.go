package main

import (
	// Uncomment this line to pass the first stage

	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	// bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

const (
	timeout = 30 * time.Second
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
		return "", fmt.Errorf("Unable to decode hex info hash %s: %w", i.hash, err)
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
		return nil, fmt.Errorf("Unable to encode torrent info %v: %w", m, err)
	}

	infoHash := sha1.New()

	_, err = infoHash.Write([]byte(encodedInfo))
	if err != nil {
		return nil, fmt.Errorf("Unable to hash torrent info %s: %w", encodedInfo, err)
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
				return "", fmt.Errorf("Unable to encode key %s in map %v: %w", key, v, err)
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

	if peersString, ok := m["peers"].(string); ok {
		var peers []string
		for i := 0; i < len(peersString); i += 6 {
			peerIp := net.IP(peersString[i : i+4])
			peerPort := binary.BigEndian.Uint16([]byte(peersString[i+4 : i+6]))
			peers = append(peers, fmt.Sprintf("%s:%d", peerIp, peerPort))
		}

		t.peers = peers
	} else {
		return nil, fmt.Errorf("Invalid or missing 'peers'")
	}

	return &t, nil
}

func getTrackerInfo(m *metaInfo) (*trackerResponse, error) {
	baseUrl, err := url.Parse(m.announce)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse tracker url %s: %w", m.announce, err)
	}

	query := baseUrl.Query()

	decodedInfoHash, err := m.info.getDecodedInfoHash()
	if err != nil {
		return nil, fmt.Errorf("Unable to get decoded info hash %s: %w", m.info.hash, err)
	}

	params := map[string]string{
		"info_hash":  decodedInfoHash,
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
		return nil, fmt.Errorf("Unable to get tracker info from url %s: %w", baseUrl.String(), err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Unable to read tracker response body: %w", err)
	}

	decoded, err := Decode(string(body))
	if err != nil {
		return nil, fmt.Errorf("Unable to decode tracker response body %s: %w", string(body), err)
	}

	trackerResponse, err := deserializeTrackerResponse((*decoded).(map[string]interface{}))
	if err != nil {
		return nil, fmt.Errorf("Unable to deserialize tracker response %s: %w", *decoded, err)
	}

	return trackerResponse, nil
}

type messageId uint8

const (
	Bitfield   messageId = 5
	Interested messageId = 2
	Unchoke    messageId = 1
	Request    messageId = 6
	Piece      messageId = 7
)

type peerConnection struct {
	peerId   string
	conn     net.Conn
	reader   *bufio.Reader
	writer   *bufio.Writer
	metaInfo *metaInfo
}

type handshakeMessage struct {
	ProtocolLength uint8
	Protocol       [19]byte
	Reserved       [8]byte
	InfoHash       [20]byte
	PeerId         [20]byte
}

type payload interface{}

type unknownPayload struct {
	data []byte
}

type emptyPayload struct{}

type requestPayload struct {
	Index  uint32
	Begin  uint32
	Length uint32
}

type piecePayload struct {
	Index uint32
	Begin uint32
	Block []byte
}

type message struct {
	MessageLength uint32
	MessageId     messageId
	Payload       payload
}

func (p *peerConnection) sendHandshake() error {
	var buffer bytes.Buffer

	var infoHashBytesArray [20]byte
	infoHashBytesSlice, err := hex.DecodeString(p.metaInfo.info.hash)
	if err != nil {
		return fmt.Errorf("Unable to decode hex info hash bytes %s: %w", p.metaInfo.info.hash, err)
	}

	copy(infoHashBytesArray[:], infoHashBytesSlice)

	peerHandshakeMessageRequest := &handshakeMessage{
		ProtocolLength: 19,
		Protocol:       [19]byte{'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't', ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'},
		Reserved:       [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
		InfoHash:       infoHashBytesArray,
		PeerId:         [20]byte{'0', '0', '1', '1', '2', '2', '3', '3', '4', '4', '5', '5', '6', '6', '7', '7', '8', '8', '9', '9'},
	}

	err = binary.Write(&buffer, binary.BigEndian, peerHandshakeMessageRequest)
	if err != nil {
		return fmt.Errorf("Unable to write peer handshake message to buffer: %w", err)
	}

	_, err = p.conn.Write(buffer.Bytes())
	if err != nil {
		return fmt.Errorf("Unable to write handshake message: %w", err)
	}

	err = p.writer.Flush()
	if err != nil {
		return fmt.Errorf("Unable to flush writer: %w", err)
	}

	return nil
}

func (pn *peerConnection) receiveHandshake() (string, error) {
	resp := make([]byte, 68)
	_, err := pn.reader.Read(resp)
	if err != nil {
		return "", fmt.Errorf("Unable to read handshake message: %w", err)
	}

	var peerHandshakeMessageResponse handshakeMessage

	if err = binary.Read(bytes.NewReader(resp), binary.BigEndian, &peerHandshakeMessageResponse); err != nil {
		return "", fmt.Errorf("Unable to deserialize handshake message: %w", err)
	}

	return hex.EncodeToString(peerHandshakeMessageResponse.PeerId[:]), nil
}

func (p *peerConnection) handshake() (string, error) {
	if err := p.sendHandshake(); err != nil {
		return "", fmt.Errorf("Unable to send handshake to peer: %v", err)
	}

	peerId, err := p.receiveHandshake()
	if err != nil {
		return "", fmt.Errorf("Unable to receive handshake from peer: %v", err)
	}

	return peerId, nil
}

func (pn *peerConnection) sendMessage(message *message) error {
	timer := time.NewTimer(timeout)
	doneChan := make(chan bool)
	errorChan := make(chan error)

	go func() {
		var buffer bytes.Buffer

		if err := binary.Write(&buffer, binary.BigEndian, message.MessageLength); err != nil {
			errorChan <- fmt.Errorf("Unable to write message length to buffer: %w", err)
			return
		}

		if err := binary.Write(&buffer, binary.BigEndian, message.MessageId); err != nil {
			errorChan <- fmt.Errorf("Unable to write message id to buffer: %w", err)
			return
		}

		if err := binary.Write(&buffer, binary.BigEndian, message.Payload); err != nil {
			errorChan <- fmt.Errorf("Unable to write message payload to buffer: %w", err)
			return
		}

		_, err := pn.writer.Write(buffer.Bytes())
		if err != nil {
			errorChan <- fmt.Errorf("Unable to write message to peer: %w", err)
			return
		}

		err = pn.writer.Flush()
		if err != nil {
			errorChan <- fmt.Errorf("Unable to flush writer: %w", err)
			return
		}

		doneChan <- true
	}()

	select {
	case <-timer.C:
		return fmt.Errorf("Timeout while sending message")
	case err := <-errorChan:
		return err
	case <-doneChan:
		return nil
	}
}

func (pn *peerConnection) receiveMessage() (*message, error) {
	timer := time.NewTimer(timeout)
	doneChan := make(chan *message)
	errorChan := make(chan error)

	go func() {
		var message message
		lengthBuffer := make([]byte, 4)

		_, err := pn.conn.Read(lengthBuffer)
		if err != nil {
			errorChan <- fmt.Errorf("Unable to read message: %w", err)
			return
		}

		message.MessageLength = binary.BigEndian.Uint32(lengthBuffer)

		messageBuffer := make([]byte, message.MessageLength)
		n, err := io.ReadFull(pn.reader, messageBuffer)
		if err != nil {
			errorChan <- fmt.Errorf("Unable to read message of length %d: %w", message.MessageLength, err)
			return
		}

		if n != int(message.MessageLength) {
			errorChan <- fmt.Errorf("Expected to read %d bytes, but read %d bytes", message.MessageLength, n)
		}

		message.MessageId = messageId(messageBuffer[0])

		switch message.MessageId {
		case Bitfield:
			message.Payload = unknownPayload{
				data: messageBuffer[1:],
			}
		case Interested:
			message.Payload = emptyPayload{}
		case Unchoke:
			message.Payload = emptyPayload{}
		case Piece:
			message.Payload = piecePayload{
				Index: binary.BigEndian.Uint32(messageBuffer[1:5]),
				Begin: binary.BigEndian.Uint32(messageBuffer[5:9]),
				Block: messageBuffer[9:],
			}
		}

		doneChan <- &message
	}()

	select {
	case <-timer.C:
		return nil, fmt.Errorf("Timeout while reading message")
	case err := <-errorChan:
		return nil, err
	case message := <-doneChan:
		return message, nil
	}
}

func (p *peerConnection) close() {
	p.writer.Flush()
	p.conn.Close()
}

func NewPeerConnection(metaInfo *metaInfo, peer string) (*peerConnection, error) {
	conn, err := net.Dial("tcp", peer)
	if err != nil {
		return nil, fmt.Errorf("Unable to dial peer %s: %w", peer, err)
	}

	peerConnection := &peerConnection{
		conn:     conn,
		metaInfo: metaInfo,
		reader:   bufio.NewReader(conn),
		writer:   bufio.NewWriter(conn),
	}

	peerId, err := peerConnection.handshake()
	if err != nil {
		return nil, fmt.Errorf("Unable to handshake with peer %s: %v", peer, err)
	}

	peerConnection.peerId = peerId

	return peerConnection, nil
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

func downloadPieces(pieceNumber int, torrent *metaInfo, peer string) (*bytes.Buffer, error) {
	peerConnection, err := NewPeerConnection(torrent, peer)
	if err != nil {
		return nil, fmt.Errorf("Unable to create connection: %w", err)
	}

	defer peerConnection.close()

	bitfieldMessage, err := peerConnection.receiveMessage()
	if err != nil {
		return nil, fmt.Errorf("Unable to receive bitfield message: %w", err)
	}

	if bitfieldMessage.MessageId != Bitfield {
		return nil, fmt.Errorf("Expected bitfield message but got %d", bitfieldMessage.MessageId)
	}

	if err := peerConnection.sendMessage(
		&message{
			MessageLength: 1,
			MessageId:     Interested,
			Payload:       emptyPayload{},
		},
	); err != nil {
		return nil, fmt.Errorf("Unable to send interested message: %w", err)
	}

	unchokeMessage, err := peerConnection.receiveMessage()
	if err != nil {
		return nil, fmt.Errorf("Unable to receive unchoke message: %v", err)
	}

	if unchokeMessage.MessageId != Unchoke {
		return nil, fmt.Errorf("Expected unchoke message but got %d", unchokeMessage.MessageId)
	}

	// Number of pieces in the torrent
	totalLength := torrent.info.length
	pieceLength := torrent.info.pieceLength
	totalNumPieces := int(math.Ceil(float64(totalLength) / float64(pieceLength)))

	// Number of blocks in a typical piece
	pieceBlockLength := 16 * 1024
	totalNumPieceBlocks := pieceLength / pieceBlockLength

	// Number of blocks if it's the last piece. Also, calculate the length
	lastBlockLength := 0
	// If it's the final piece,
	if totalNumPieces == pieceNumber+1 {
		// find if that final piece will have smaller length than pieceLength
		lastPieceLength := totalLength % pieceLength
		// if it is indeed smaller
		if lastPieceLength != 0 {
			// then calculate the actual number of blocks that may be needed
			totalNumPieceBlocks = int(math.Ceil(float64(lastPieceLength) / float64(pieceBlockLength)))
			// and find how long the last block of the piece will be
			lastBlockLength = lastPieceLength % pieceBlockLength
		}
	}

	var pieceBuffer bytes.Buffer
	for i := 1; i < totalNumPieceBlocks+1; i++ {
		start := (i - 1) * pieceBlockLength
		end := start + pieceBlockLength

		// If we are at last block of the piece and there is a lastBlockLength value (i.e., the piece in question is the last piece), then we need to adjust the end
		if i == totalNumPieceBlocks && lastBlockLength != 0 {
			end = start + lastBlockLength
			fmt.Println(start, end, lastBlockLength)
		}

		blockLength := end - start

		if err := peerConnection.sendMessage(
			&message{
				MessageLength: 13,
				MessageId:     Request,
				Payload: requestPayload{
					Index:  uint32(pieceNumber),
					Begin:  uint32(start),
					Length: uint32(blockLength),
				},
			},
		); err != nil {
			return nil, fmt.Errorf("Unable to send request block %d/%d for piece # %d: %w", i, totalNumPieceBlocks, pieceNumber, err)
		}

		pieceMessage, err := peerConnection.receiveMessage()
		if err != nil {
			return nil, fmt.Errorf("Unable to receive piece block %d/%d for piece # %d: %w", i, totalNumPieceBlocks, pieceNumber, err)
		}

		if pieceMessage.MessageId != Piece {
			return nil, fmt.Errorf("Expected piece message for piece block %d/%d for piece # %d but got %d", i, totalNumPieceBlocks, pieceNumber, pieceMessage.MessageId)
		}

		_, err = pieceBuffer.Write(pieceMessage.Payload.(piecePayload).Block)
		if err != nil {
			return nil, fmt.Errorf("Unable to buffer piece block %d/%d for piece # %d: %w", i, totalNumPieceBlocks, pieceNumber, err)
		}
	}

	return &pieceBuffer, nil

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

		trackerResponse, err := getTrackerInfo(torrent)
		if err != nil {
			log.Fatalf("Unable to get tracker info for torrent %v: %v", torrent, err)
		}

		for _, peer := range trackerResponse.peers {
			fmt.Printf("%s\n", peer)
		}
	case "handshake":
		torrent, err := getMetaInfo(os.Args[2])
		if err != nil {
			log.Fatalf("Unable to get meta info for file name %s: %v", os.Args[2], err)
		}

		peerConnection, err := NewPeerConnection(torrent, os.Args[3])
		if err != nil {
			log.Fatalf("Unable to create connection for peer %s: %v", os.Args[3], err)
		}

		fmt.Printf("Peer ID: %s\n", peerConnection.peerId)
	case "download_piece":
		pieceNumber, err := strconv.Atoi(os.Args[5])
		if err != nil {
			log.Fatalf("Unable to parse piece number %s: %v", os.Args[5], err)
		}

		pieceFileName := os.Args[3]

		torrent, err := getMetaInfo(os.Args[4])
		if err != nil {
			log.Fatalf("Unable to get meta info for file name %s: %v", os.Args[4], err)
		}

		trackerResponse, err := getTrackerInfo(torrent)
		if err != nil {
			log.Fatalf("Unable to get tracker info for torrent %v: %v", torrent, err)
		}

		peer := trackerResponse.peers[0]

		pieceBuffer, err := downloadPieces(pieceNumber, torrent, peer)
		if err != nil {
			log.Fatalf("Unable to download piece # %d from peer %s: %v", pieceNumber, peer, err)
		}

		pieceHash := sha1.Sum(pieceBuffer.Bytes())
		encodedPieceHash := hex.EncodeToString(pieceHash[:])
		if encodedPieceHash != torrent.info.pieces[pieceNumber] {
			log.Fatalf("Piece # %d hash %s does not match expected hash %s", pieceNumber, encodedPieceHash, torrent.info.pieces[pieceNumber])
		}

		dir := filepath.Dir(pieceFileName)
		if err = os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Unable to create directory %s: %v", dir, err)
		}

		file, err := os.Create(pieceFileName)
		if err != nil {
			log.Fatalf("Unable to create file %s: %v", pieceFileName, err)
		}
		defer file.Close()

		_, err = pieceBuffer.WriteTo(file)
		if err != nil {
			log.Fatalf("Unable to write piece # %d to file %s: %v", pieceNumber, pieceFileName, err)
		}

		fmt.Printf("Piece %d downloaded to %s\n", pieceNumber, pieceFileName)
	default:
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
