package client

// MAKE SURE YOU'RE SUPPORTING MULTI-USER SESSIONS

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

var forbidden_pws = []string{"123456", "123456789", "qwerty", "password", "12345", "qwerty123", "1q2w3e", "12345678", "111111", "1234567890"}

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

// ----- INVITE CLASS ----- $
type Invite struct {
	File                 string
	Owner                string
	Signed               []byte
	Cypher_data_location []byte //uuid.UUID
	Signature_verify     []byte
}

// ----- FILE CLASSES -----
// contains the data of the file in chyptertxt and hmac
type File_container struct {
	Chypter_text []byte
	Hmac         []byte
}

type File struct {
	Uuid    uuid.UUID // this is going to change when invite is revoked
	file_ll uuid.UUID
	Owner   string
	Editors map[string]uuid.UUID // not sure about this
	Hmac    []byte
	Key     []byte
	Iv      []byte
}

type File_sentinel struct {
	Next uuid.UUID
	End  uuid.UUID
}

type File_node struct {
	Next uuid.UUID
	Data []byte
}

// type File_linked_list struct {
// 	Sentinel *File_node
// 	Size     int
// }

// func init_file_fll() *File_linked_list { // return type ??
// 	sent := &File_node{Data: []byte("sentinel"), Next: uuid.Nil}
// 	return &File_linked_list{Sentinel: sent, Size: 0}
// }

// ----- USER CLASS -----
// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	uuid             uuid.UUID
	Username         string
	private_key      userlib.PKEDecKey      // userlib.PrivateKeyType // needs to be stored in the keystore ????
	public_key       userlib.PKEEncKey      // userlib.PublicKeyType
	signature_key    userlib.PrivateKeyType // keep this one private
	signature_verify userlib.PublicKeyType  // i can share this one
	files            map[string]uuid.UUID
	invites_map      map[string]uuid.UUID // invites received
	master_key       []byte               // to check if you're the owner of the file & remove persmission

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// Generates a new UUID - it computes a 64-bit hash value
func GenerateUUID(username string, password string) uuid.UUID {
	// Hash the username and password using FNV-1a
	hash := userlib.Argon2Key([]byte(password), []byte(username), 16)
	storageKey := uuid.NewSHA1(uuid.Nil, hash)
	return storageKey
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {

	// Check if the username or psw are empty
	if username == "" || password == "" {
		return nil, errors.New("empty username or password")
	}

	// Check if a user with the same username already exists
	_, exists := userlib.KeystoreGet(username + "public-key")
	if exists {
		return nil, errors.New("username already taken")
	}

	// // Check that the psw choice is not common
	// for _, p := range forbidden_pws {
	// 	if p == password {
	// 		return nil, errors.New("you are not allowed to use common passwords")
	// 	}
	// }

	// creating Public & Private keys
	var pk userlib.PKEEncKey // HashKDF
	var sk userlib.PKEDecKey
	pk, sk, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	pk, sk, err_key := userlib.PKEKeyGen()
	if err_key != nil {
		return nil, err_key
	}
	// creating Signature
	sign_key, sign_verify, err := userlib.DSKeyGen()

	// saving public-key & signature-verify into keystore
	var err_pub_key error = userlib.KeystoreSet(username+"public-key", pk)
	if err_pub_key != nil {
		return nil, err_pub_key
	}
	var err_sign_key error = userlib.KeystoreSet(username+"key-verify", sign_verify)
	if err_sign_key != nil {
		return nil, err_sign_key
	}

	client := User{
		uuid:             GenerateUUID(username, password),
		Username:         username,
		private_key:      sk,          // CHANGE THIS - how to generate private key?
		public_key:       pk,          // CHANGE THIS - how to generate public key?
		signature_key:    sign_key,    // this one must kept private
		signature_verify: sign_verify, // i can share this one
		files:            make(map[string]uuid.UUID),
		invites_map:      make(map[string]uuid.UUID),
		master_key:       userlib.RandomBytes(16)}

	// storing to datastore
	marshalled_bytes, err := json.Marshal(client)
	if err != nil {
		return nil, errors.New("error while marshalling user")
	}
	// encrypt bytes

	// SAVING TO DATASTORE
	// generating encrypted key
	salt := userlib.Hash([]byte(username))
	enc_key := userlib.Argon2Key([]byte(password), salt, 16)

	// generating chyper-text
	iv := userlib.RandomBytes(16)
	chyper_text_bytes := userlib.SymEnc(enc_key, iv, marshalled_bytes)

	// saving chyper text to data-store
	userlib.DatastoreSet(client.uuid, chyper_text_bytes)

	return &client, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	// retrieving chypertext of user
	cypher_text, _ := userlib.DatastoreGet(GenerateUUID(username, password))

	// regenerating the key to get the user
	enc_key := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)

	// decrypting the user
	marshal_user := userlib.SymDec(enc_key, cypher_text)

	// unmarshalling the user to retrieve the object
	var userdata User
	json.Unmarshal(marshal_user, userdata)
	return &userdata, nil
	return nil, errors.New("user not found or invalid credentials")
}

// HELPER FUNCTIONS
func (userdata *User) owns(filename string) bool {
	// go through the map of files and check if the filename is there
	if _, ok := userdata.files[filename]; ok {
		return true
	}
	return false
}

// when calling this method, always marshal first the data
func save_to_datastore(uuid uuid.UUID,
	data []byte,
	hmac_key []byte,
	symm_key []byte,
	iv []byte) (err error) {

	var container File_container
	container.Chypter_text = userlib.SymEnc(symm_key, iv, data)

	hmac, err_hmac := userlib.HMACEval(hmac_key, container.Chypter_text)
	if err_hmac != nil {
		return err_hmac
	}

	container.Hmac = hmac

	marshalled_container, err_mar := json.Marshal(container)
	if err_mar != nil {
		return err_mar
	}

	userlib.DatastoreSet(uuid, marshalled_container)
	return nil
}

func get_from_datastore(uuid uuid.UUID,
	hmac []byte,
	symm_key []byte) (data []byte, err error) {

	bytes, empty := userlib.DatastoreGet(uuid)
	if !empty {
		return nil, errors.New("Empty UUID")
	}

	// unmarshalling the content
	var container File_container
	err_unmar := json.Unmarshal(bytes, &container)
	if err_unmar != nil {
		return nil, errors.New("Error when unmarshalling")
	}

	//cheking the HMACs are the same
	is_same, err_hmac := hmac_checker(container.Chypter_text, container.Hmac, hmac)
	if !is_same {
		return nil, err_hmac
	}

	return userlib.SymDec(symm_key, container.Chypter_text), nil
}

func hmac_checker(ciphertext []byte,
	hmac []byte,
	key []byte) (equal bool, err error) {

	hmac_from_cipher, err_hmac := userlib.HMACEval(key, ciphertext)
	if err_hmac != nil {
		return false, err_hmac
	}

	//Check if HMAC's Ciphertext is equal to the stored HMAC
	if !userlib.HMACEqual(hmac_from_cipher, hmac) {
		return false, errors.New("HMACs are different")
	}
	return true, nil
}

func get_file(master_key []byte, filename string) (file_obj *File, file_s *File_sentinel, err error) {

	// regenerating & getting keys
	key, key_err := userlib.HashKDF(master_key, []byte(filename))
	if key_err != nil {
		return nil, nil, key_err
	}

	_uuid, hmac_key, symm_key := key[:16], key[16:32], key[48:64]
	invite_uuid, err_invite := uuid.FromBytes(_uuid)
	if err_invite != nil {
		return nil, nil, err_invite
	}

	var file File // 1st return
	file_bytes, _ := get_from_datastore(invite_uuid, hmac_key, symm_key)
	err_unmar := json.Unmarshal(file_bytes, &file) // error here
	if err_unmar != nil {
		return nil, nil, err_unmar
	}

	var sentinel File_sentinel // 2nd return
	sentinel_bytes, _ := get_from_datastore(file.Uuid, file.Hmac, file.Key)
	err_unmar2 := json.Unmarshal(sentinel_bytes, &sentinel)
	if err_unmar2 != nil {
		return nil, nil, err_unmar2
	}

	return &file, &sentinel, nil
}

// TODO
func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	if !userdata.owns(filename) {

		file_obj := File{
			Uuid:    uuid.New(),
			file_ll: uuid.Nil,
			Owner:   userdata.Username,
			Editors: make(map[string]uuid.UUID),
			Hmac:    userlib.RandomBytes(16),
			Key:     userlib.RandomBytes(16), // need to first generate this key by the owner
			Iv:      userlib.RandomBytes(16)}

		// Creating & Saving "head" to datastore
		file_head := File_sentinel{Next: uuid.New(), End: uuid.Nil}
		file_head_bytes, _ := json.Marshal(file_head)
		err_save := save_to_datastore(file_obj.Uuid, file_head_bytes, file_obj.Hmac, file_obj.Key, file_obj.Iv)
		if err_save != nil {
			return err_save
		}

		// Creating & Saving "File Node" to datastore
		file_n := File_node{Data: content, Next: uuid.New()}
		file_n_bytes, _ := json.Marshal(file_n)
		err_save_node := save_to_datastore(file_obj.Uuid, file_n_bytes, file_obj.Hmac, file_obj.Key, file_obj.Iv)
		if err_save_node != nil {
			return err_save_node
		}

		// Creating & Saving "End Node" to datastore
		file_end := File_node{Data: []byte{}, Next: uuid.Nil}
		file_end_bytes, _ := json.Marshal(file_end)
		err_save_end := save_to_datastore(file_obj.Uuid, file_end_bytes, file_obj.Hmac, file_obj.Key, file_obj.Iv)
		if err_save_end != nil {
			return err_save_end
		}
		userdata.files[filename] = file_obj.Uuid
		return nil
		// User Map Invite ???
		// What about invitation here?
	}

	file, sentinel, _ := get_file(userdata.master_key, filename)

	// creating "node" & converting it into []bytes
	node := File_node{Next: uuid.New(), Data: content}
	node_bytes, err_mar := json.Marshal(node)
	if err_mar != nil {
		return err_mar
	}
	// saving "node" []bytes to datastore
	node_err := save_to_datastore(sentinel.Next, node_bytes, file.Hmac, file.Key, file.Iv)
	if node_err != nil {
		return node_err
	}

	// creating "end node" & converting it into []bytes
	end_node := File_node{Next: uuid.Nil, Data: []byte{}}
	end_node_bytes, err_end_node := json.Marshal(end_node)
	if err_end_node != nil {
		return err_end_node
	}
	// saving "end node" []bytes to datastore
	end_err_saving := save_to_datastore(file.Uuid, end_node_bytes, file.Hmac, file.Key, file.Iv)
	if end_err_saving != nil {
		return end_err_saving
	}

	// updating "sentinel"
	sentinel.End = node.Next
	sentinel_bytes, err_sentinel := json.Marshal(sentinel)
	if err_sentinel != nil {
		return err_sentinel
	}
	// saving updated "sentinel" to datastore
	err_saving_sentinel := save_to_datastore(file.Uuid, sentinel_bytes, file.Hmac, file.Key, file.Iv)
	if err_saving_sentinel != nil {
		return err_saving_sentinel
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	file, sentinel, err_get_file := get_file(userdata.master_key, filename)
	if err_get_file != nil {
		return err_get_file
	}

	// creating & saving "old end" node
	old_end := File_node{Next: uuid.New(), Data: content}
	old_end_bytes, err_old_end := json.Marshal(old_end)
	if err_old_end != nil {
		return err_old_end
	}

	err_saving_end_node := save_to_datastore(sentinel.End, old_end_bytes, file.Hmac, file.Key, file.Iv)
	if err_saving_end_node != nil {
		return err_saving_end_node
	}

	// creating & saving "new end" node
	new_end := File_node{Next: uuid.Nil, Data: []byte{}}
	new_end_bytes, err_new_end := json.Marshal(new_end)
	if err_new_end != nil {
		return err_new_end
	}

	err_saving_new_end := save_to_datastore(old_end.Next, new_end_bytes, file.Hmac, file.Key, file.Iv)
	if err_saving_new_end != nil {
		return err_saving_new_end
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	var file_bytes []byte
	// file = fileAccess & headOFfile = sentinel
	file, sentinel, err_get_file := get_file(userdata.master_key, filename)
	if err_get_file != nil {
		return nil, err_get_file
	}

	// getting "current node" from data store & unmarshalling it
	var curr_node File_node
	curr_node_bytes, err_curr_node_bytes := get_from_datastore(sentinel.Next, file.Hmac, file.Key)
	if err_curr_node_bytes != nil {
		return nil, err_curr_node_bytes
	}
	err_unmarshal_curr_node := json.Unmarshal(curr_node_bytes, curr_node)
	if err_unmarshal_curr_node != nil {
		return nil, err_unmarshal_curr_node
	}

	file_bytes = append(file_bytes, curr_node.Data...)

	// file traversal
	for curr_node.Next != uuid.Nil {
		curr_node_bytes, traverse_err := get_from_datastore(curr_node.Next, file.Hmac, file.Key)
		if traverse_err != nil {
			return nil, traverse_err
		}

		err_mar := json.Unmarshal(curr_node_bytes, curr_node)
		if err_mar != nil {
			return nil, err_mar
		}

		file_bytes = append(file_bytes, curr_node.Data...)
	}

	// OLD CODE BASE
	// storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	// if err != nil {
	// 	return nil, err
	// }
	// dataJSON, ok := userlib.DatastoreGet(storageKey)
	// if !ok {
	// 	return nil, errors.New(strings.ToTitle("file not found"))
	// }
	// err = json.Unmarshal(dataJSON, &content)
	// return content, err

	return file_bytes, nil
}

// TODO
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// hash_editor = recipientUsername
	// hash_editor := hex.EncodeToString(userlib.Hash([]byte(recipientUsername)))

	file, sentinel, err_get_file := get_file(userdata.master_key, filename)
	if err_get_file != nil {
		return uuid.Nil, err_get_file
	}

	if userdata.Username == file.Owner { // is the sender is the owner

		invite_address, err_invite := userlib.HashKDF(userdata.master_key, []byte(recipientUsername+filename))
		if err_invite != nil {
			return uuid.Nil, err_invite
		}
		invite_uuid, err_uuid := uuid.FromBytes(invite_address[:16])
		if err_uuid != nil {
			return uuid.Nil, err_uuid
		}

		// (1) Creating Cyphertext
		plain_txt := userdata.files[filename] // file location
		mar_plain_txt, mar_err := json.Marshal(plain_txt)
		if mar_err != nil {
			return uuid.Nil, mar_err
		}
		cyphertxt, err_cyp := userlib.PKEEnc(userdata.public_key, mar_plain_txt)
		if err_cyp != nil {
			return uuid.Nil, err_cyp
		}
		// (2) Creating Signature
		signature, err_sig := userlib.DSSign(userdata.private_key, cyphertxt)
		if err_sig != nil {
			return uuid.Nil, err_sig
		}
		// (3) Creating Invitation
		invitation := Invite{Cypher_data_location: cyphertxt, Signature_verify: signature}
		invitation_bytes, err_marshalling := json.Marshal(invitation)
		if err_marshalling != nil {
			return uuid.Nil, err_marshalling
		}
		// (4) Saving Invitation
		err_saving := save_to_datastore(invite_uuid, invitation_bytes, file.Hmac, file.Key, file.Iv)
		if err_saving != nil {
			return uuid.Nil, err_saving
		}

		// (5) Adding "Editor" to "Editors  Map"
		file.Editors[recipientUsername] = invite_uuid

		// (6) Saving File
		file_bytes, err_marshalling_file := json.Marshal(file)
		if err_marshalling_file != nil {
			return uuid.Nil, err_marshalling_file
		}

		err_saving_file := save_to_datastore(sentinel.Next, file_bytes, file.Hmac, file.Key, file.Iv)
		if err_saving_file != nil {
			return uuid.Nil, err_saving_file
		}
		return invite_uuid, nil
	} else { // If the sender is not the owner
		// (1) Creating Cyphertext
		plain_txt := userdata.invites_map[filename] // file location
		mar_plain_txt, mar_err := json.Marshal(plain_txt)
		if mar_err != nil {
			return uuid.Nil, mar_err
		}
		cyphertxt, err_cyp := userlib.PKEEnc(userdata.public_key, mar_plain_txt)
		if err_cyp != nil {
			return uuid.Nil, err_cyp
		}

		// (2) Creating Signature
		signature, err_sig := userlib.DSSign(userdata.private_key, cyphertxt)
		if err_sig != nil {
			return uuid.Nil, err_sig
		}

		// (3) Creating Invitation
		invitation := Invite{File: filename, Owner: userdata.Username, Cypher_data_location: cyphertxt, Signature_verify: signature}
		invitation_bytes, err_marshalling := json.Marshal(invitation)
		if err_marshalling != nil {
			return uuid.Nil, err_marshalling
		}

		// (4) Saving Invitation
		err_saving := save_to_datastore(userdata.invites_map[filename], invitation_bytes, file.Hmac, file.Key, file.Iv)
		if err_saving != nil {
			return uuid.Nil, err_saving
		}

		// (5) Adding "Editor" to "Editors  Map"
		file.Editors[recipientUsername] = userdata.invites_map[filename]

		// (6) Saving File
		file_bytes, err_marshalling_file := json.Marshal(file)
		if err_marshalling_file != nil {
			return uuid.Nil, err_marshalling_file
		}

		return userdata.invites_map[filename], save_to_datastore(sentinel.Next, file_bytes, file.Hmac, file.Key, file.Iv)
	}
	// the user does not have access to the file nor is the owner
	return uuid.Nil, errors.New("User does not have access to file nor is the owner")
}

// TODO
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	// The caller already has a file with the given filename in their personal file namespace
	_, ok := userdata.files[filename]
	if !ok {
		return errors.New("The caller already has a file with the given filename in their personal file namespace")
	}

	// check invitation is no longer valid due to revocation.
	_, ok = userdata.invites_map[filename]
	if !ok {
		return errors.New("check invitation is no longer valid due to revocation")
	}
	// (1) Verify that invitation comes from the owner
	// (1.1) Getting the public key of the sender
	public_key, pk_exist := userlib.KeystoreGet(senderUsername + "public-key")
	if !pk_exist {
		return nil
	}
	// (1.2) Getting the signature from the sender
	signature, sign_exist := userlib.KeystoreGet(senderUsername + "key-verify")
	if !sign_exist {
		return nil
	}

	// (1.3) Getting the cyphertext from invitationPtr
	cypher_text, err := userlib.DatastoreGet(invitationPtr)
	if !err {
		return nil
	}

	// (1.4) Verify the signature
	valid_signature := userlib.DSVerify(public_key, cypher_text, signature.PubKey.N.Bytes())
	if valid_signature != nil {
		return nil
	}
	// (2) Decrypt the chyper text to get file location
	plain_txt, err_cyp := userlib.PKEDec(userdata.private_key, cypher_text)
	if err_cyp != nil {
		return nil
	}

	// (3) Unmarshal the invitation
	var invitation Invite
	err_mar := json.Unmarshal(plain_txt, &invitation)
	if err_mar != nil {
		return nil
	}

	// (4) Verify that the invitation is for the correct file
	if invitation.File != filename {
		return nil
	}
	// (5) Verify that the invitation is for the correct owner
	if invitation.Owner != senderUsername {
		return nil
	}

	// (6) Get the file location
	file_location := invitation.Cypher_data_location

	// (7) Unmarshal file_location to get uui.UUID
	var file_uuid uuid.UUID
	err_marshalling := json.Unmarshal(file_location, &file_uuid)
	if err_marshalling != nil {
		return nil
	}

	// (8) Add "invite"	 to "invites_map"
	userdata.invites_map[filename] = file_uuid
	return nil
}

// TODO
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	// (1) Get the file location from the user's file map
	file_location, ok := userdata.files[filename]
	if !ok {
		return errors.New("The caller already has a file with the given filename in their personal file namespace")
	}
	// (2) Get the file from the file location
	file_bytes, err := userlib.DatastoreGet(file_location)
	if !err {
		return nil
	}
	// (3) Unmarshal the file
	var file File
	err_mar := json.Unmarshal(file_bytes, &file)
	if err_mar != nil {
		return err_mar
	}
	// (4) Check if the user is the owner
	if file.Owner != userdata.Username {
		return errors.New("The user is not the owner")
	}

	// (6) Move the file to a different location in datastore
	new_file_location := uuid.New()
	userlib.DatastoreSet(new_file_location, file_bytes)

	// (7) Update the file location in the user's file map
	userdata.files[filename] = new_file_location

	// (8) Update the file's Editor map with new location for every user except the recipient
	for user, _ := range file.Editors {
		if user != recipientUsername {
			file.Editors[user] = new_file_location
		}
	}
	// (9) Remove recipient from file's Editor map
	delete(file.Editors, recipientUsername)

	return nil
}
