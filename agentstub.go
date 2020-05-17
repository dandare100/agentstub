package main

import (
	"encoding/binary"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	b64 "encoding/base64"

	"log"
)

func main() {

	//get the start dir
	dirPtr := flag.String("dir", "/tmp", "The parent directory to start searching in.")

	//get the action to perform
	act := flag.String("action", "listallids", "[listallids, listidsforagent, listagentpaths, pvtkeyop, queryext]")

	//agent path to cater for 1
	agentPath := flag.String("agentpath", "none", "The agent path for the action to use when processing")

	keyblobb64 := flag.String("keyblobb64", "none", "The base 64 representation of the public key blob")

	keyopdatab64 := flag.String("keyopdatab64", "none", "The data to perform the private key operation on")

	extquery := flag.String("extquery", "all", "The extension query string")

	flag.Parse()

	//some validations
	//does the start dir exist ?
	_, e := os.Stat(*dirPtr)
	if e != nil {
		log.Fatalf("Eish, cannot process directory %s. Does it exist ?", *dirPtr)
	}

	log.Printf("Processing action %s", *act)

	switch *act {

	case "listallids":
		listAllIds(getSockets(*dirPtr))

	case "listidsforagent":
		listAllIDsForAgent(*agentPath)

	case "listagentpaths":
		socketList := getSockets(*dirPtr)
		log.Printf("Found %d possible sockets.", len(socketList))
		for _, file := range socketList {
			log.Printf(file)
		}

	case "pvtkeyop":
		performPvtKeyOp(*keyblobb64, *keyopdatab64, *agentPath)

	case "queryext":
		queryext(*extquery, *agentPath)

	default:
		log.Printf("Unrecognized action %s.", *act)
	}
}

func listAllIds(socketList []string) {
	for _, file := range socketList {
		listAllIDsForAgent(file)
	}
}

func listAllIDsForAgent(socketpath string) {

	log.Printf("Retrieving identities from %s", socketpath)

	//length
	var sendbuf [4]byte

	//list identities
	message := []byte{0x0b}

	//add the length header
	binary.BigEndian.PutUint32(sendbuf[:], uint32(len(message)))

	message = append(sendbuf[:], message...)

	sendRequestAndProcessResponse(message, socketpath)

}

func getSockets(startdir string) []string {

	retList := []string{}
	filepath.Walk(startdir, func(path string, f os.FileInfo, err error) error {

		if strings.HasPrefix(path, startdir+"/ssh") {

			fi, err := os.Stat(path)

			if err != nil {
				log.Fatalf("Fatal error checking path for sockets")
			}
			//mask out all other bits to check for socket
			if fi.Mode()&1000000000 == os.ModeSocket {
				retList = append(retList, path)
			}

		}
		return nil
	})
	log.Printf("%d sockets found.", len(retList))
	return retList
}

func queryext(query, agentpath string) {
	//length
	var sendbuf [4]byte

	//list identities
	message := []byte{0x1b}

	message = append(message, make([]byte, 4)...)

	binary.BigEndian.PutUint32(message[len(message)-4:], uint32(len(query)))
	log.Printf("query is %s", query)
	message = append(message, []byte(query)...)

	//add the length header
	binary.BigEndian.PutUint32(sendbuf[:], uint32(len(message)))

	message = append(sendbuf[:], message...)

	sendRequestAndProcessResponse(message, agentpath)
}

func performPvtKeyOp(keyblobb64, keyopdatab64, agentpath string) {
	//echo -n signme | openssl dgst -sha1 -sign ~/.ssh/id_rsa | xxd
	//get the byte representation of the key blob
	keyblob, err := b64.StdEncoding.DecodeString(keyblobb64)
	if err != nil {
		log.Fatal("Could not decode base64 encoded keyblob")
	}

	//get the byte representation of the key op data
	keyopdata, err := b64.StdEncoding.DecodeString(keyopdatab64)
	if err != nil {
		log.Fatal("Could not decode base64 encoded keyopdata")
	}

	message := make([]byte, 4)

	binary.BigEndian.PutUint32(message[len(message)-4:], uint32(len(keyblob)))

	message = append(message, keyblob...)

	message = append(message, make([]byte, 4)...)

	binary.BigEndian.PutUint32(message[len(message)-4:], uint32(len(keyopdata)))

	message = append(message, keyopdata...)

	message = append(message, make([]byte, 4)...)
	//sha256 = 2 sha512 = 4
	binary.BigEndian.PutUint32(message[len(message)-4:], uint32(4))

	sendbuf := make([]byte, 4)

	binary.BigEndian.PutUint32(sendbuf[:], uint32(len(message)+1))

	sendbuf = append(sendbuf, 0xd)

	sendbuf = append(sendbuf, message...)

	sendRequestAndProcessResponse(sendbuf, agentpath)

}

func listIds(recbuf []byte) {

	//get how many ids were returned
	numids := int(binary.BigEndian.Uint32(recbuf[1:5]))
	log.Printf("There were %d identities returned.", numids)
	//create a work buffer
	workbuf := recbuf[5:]
	index := 0

	//print the id's out
	for i := 0; i < numids*2; i++ {

		//get the length of the next string
		idlen := int(binary.BigEndian.Uint32(workbuf[index : index+5]))
		//read the next string
		if i%2 == 0 {
			log.Printf("ID (b64): %s", b64.StdEncoding.EncodeToString(workbuf[index+4:index+4+idlen]))
		} else {
			log.Printf("Comment : %s", string(workbuf[index+4:index+4+idlen]))
		}
		index = index + idlen + 4
	}

}

func listKeyOpResponse(reply []byte) {

	//read the encoding type string. index starts at 5 because result type is passed in
	//and we are not using the message length
	enctypelen := binary.BigEndian.Uint32(reply[5:9])

	enctype := string(reply[9 : 9+enctypelen])

	log.Printf("Encode type : %s", enctype)

	rsasigbloblen := binary.BigEndian.Uint32(reply[9+enctypelen : 9+enctypelen+4])

	log.Printf("rsa signature blob length : %d", rsasigbloblen)

	rsasigblob := reply[9+enctypelen+4 : 9+enctypelen+4+rsasigbloblen]

	log.Printf("rsa signature blob : %x", rsasigblob)

}

func sendRequestAndProcessResponse(sendbuf []byte, agentpath string) {

	//log.Printf("Here %v", sendbuf)

	c, err := net.DialTimeout("unix", agentpath, 3*time.Second)
	if err != nil {
		log.Printf("Skipping %s.Failed to dial: %s", agentpath, err)
		return
	}

	defer c.Close()

	count, err := c.Write(sendbuf[:])
	if err != nil {
		log.Printf("Skipping %s. Write error: %s", agentpath, err)
		return
	}

	//read and process response
	reclen := make([]byte, 4)
	//read the reply length
	reclencnt, err := c.Read(reclen)
	if err != nil {
		log.Printf("Read error: %s", err)
		return
	}
	//create buffer to receive the response
	recbuf := make([]byte, binary.BigEndian.Uint32(reclen))
	//read response into buffer
	recbufcnt, err := c.Read(recbuf)
	if err != nil {
		log.Printf("Payload read error: %s", err)
		return
	}

	//splurb some sh1t
	log.Printf("Wrote %d bytes", count)
	log.Printf("Read %d bytes", reclencnt+recbufcnt)

	switch recbuf[0] {
	case 0x5:
		log.Fatal("The agent replied with a failure status. Sorry, thats all I know.")
	//SSH_AGENT_SIGN_RESPONSE
	case 0xe:
		listKeyOpResponse(recbuf)
	//SSH_AGENT_IDENTITIES_ANSWER
	case 0xc:
		listIds(recbuf)
	default:
		log.Printf("Unknown response type from agent.[%x]", recbuf[0])
	}

}
