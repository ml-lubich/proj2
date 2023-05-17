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
	pk, sk, err = userlib.PKEKeyGen()
	if err != nil {
		panic(err)
	}
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

// ----- TREE CLASS -----
type Node struct {
	id       string
	children []*Node
}

type Tree struct {
	root *Node
}

func (n *Node) GetDescendants() []*Node {
	descendants := []*Node{}
	n.collectDescendants(&descendants)
	return descendants
}

func (n *Node) collectDescendants(descendants *[]*Node) {
	for _, child := range n.children {
		*descendants = append(*descendants, child)
		child.collectDescendants(descendants)
	}
}

func (t *Tree) Insert(id string, data string, parent *Node) {
	node := &Node{id: id, data: data}
	if parent == nil {
		t.root = node
	} else {
		parent.children = append(parent.children, node)
	}
}

func (t *Tree) RemoveNode(id string) {
	t.root = t.removeNode(t.root, id)
}

func (t *Tree) removeNode(node *Node, id string) *Node {
	if node == nil {
		return nil
	}

	if node.id == id {
		return nil
	}

	resultChildren := []*Node{}
	for _, child := range node.children {
		newChild := t.removeNode(child, id)
		if newChild != nil {
			resultChildren = append(resultChildren, newChild)
		}
	}

	node.children = resultChildren
	return node
}

// ----- INVITE CLASS ----- $
type Invite struct { // points to sentinel
	File            string
	Owner           string
	Signed          []byte
	File_uuid       []byte // uuid.UUID
	File_sym_key    []byte // confidentiality: unlocks the file (needed for revocation when we rehash the file)
	File_hmac_key   []byte // integrity: hmac as well (needed for revocation when we rehash the file)
	Editor_uuid     []byte // editor class that stores the usernames of users that are authorized to edit the file in a tree structure (hierarchical structure)
	Editor_sym_key  []byte // confidentiality: (needed for revocation when we rehash the file)
	Editor_hmac_key []byte // integrity: hmac as well (needed for revocation when we rehash the file)
}

// ----- EDITOR CLASS -----
type Editors struct {
	editors_tree Node
} // TODO finish implementation for editor class

// ----- FILE CLASSES -----
// contains the data of the file in chyptertxt and hmac
type File_container struct {
	Cypher_text []byte
	Hmac        []byte
}

type File struct {
	Sentinel_uuid uuid.UUID // this is going to change when invite is revoked
	Owner         string
	Editors       map[string]uuid.UUID // not sure about this
	Hmac          []byte
	Key           []byte
	Iv            []byte
	Editors_uuid  uuid.UUID // this is going to change when invite is revoked
}

type File_sentinel struct {
	Head uuid.UUID
	End  uuid.UUID
}

type File_node struct {
	Next uuid.UUID
	Data []byte
}

// ----- USER CLASS -----
type User struct {
	uuid             uuid.UUID // own uuid
	Username         string
	private_key      userlib.PKEDecKey      // userlib.PrivateKeyType // needs to be stored in the keystore ????
	public_key       userlib.PKEEncKey      // userlib.PublicKeyType
	signature_key    userlib.PrivateKeyType // keep this one private
	signature_verify userlib.PublicKeyType  // i can share this one
	files            map[string]uuid.UUID
	invites_map      map[string]uuid.UUID // invites received
	master_key       []byte               // to check if you're the owner of the file & remove persmission
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Check if the username or psw are empty
	if username == "" || password == "" {
		return nil, errors.New("empty username or password")
	}

	// Check if a user with the same username already exists
	_, exists := userlib.KeystoreGet(username + "public-key")
	if exists {
		return nil, errors.New("User already exists with the provided username")
	}

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
		return nil, errors.New("Error while marshalling user")
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
	cypher_text, ok := userlib.DatastoreGet(GenerateUUID(username, password))
	if !ok {
		return nil, errors.New("User not found or invalid credentials")
	}

	// regenerating the key to get the user
	enc_key := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)

	// decrypting the user
	marshal_user := userlib.SymDec(enc_key, cypher_text)

	// unmarshalling the user to retrieve the object
	var userdata User
	err = json.Unmarshal(marshal_user, &userdata)
	if err != nil {
		return nil, errors.New("Error while unmarshalling user")
	}
	return &userdata, nil
}

// HELPER FUNCTIONS
// TODO
func (userdata *User) is_file_in_user_filespace(filename string) bool {
	// check if user has access to file by checking either in the files list or the invites list
	if _, ok := userdata.files[filename]; ok {
		return true
	}
	if invite_uuid, ok := userdata.invites_map[filename]; ok {

	}
	return false
}

func (userdata *User) is_owner(filename string) bool {
	// go through the map of files and check if the filename is there
	// all files that are owned by the user are stored in the files list
	// all files that the user has in their file space is store either in the files list or the invites list
	if _, ok := userdata.files[filename]; ok {
		return true
	}
	return false
}

func save_to_datastore(uuid uuid.UUID,
	obj interface{},
	hmac_key []byte,
	symm_key []byte,
	iv []byte) (err error) {

	obj_bytes, err := json.Marshal(obj)
	if err != nil {
		return errors.New("Error when marshalling")
	}

	var container File_container
	container.Cypher_text = userlib.SymEnc(symm_key, iv, obj_bytes)

	hmac, err_hmac := userlib.HMACEval(hmac_key, container.Cypher_text)
	if err_hmac != nil {
		return errors.New("error while computing HMAC")
	}

	container.Hmac = hmac

	marshalled_container, err_mar := json.Marshal(container)
	if err_mar != nil {
		return errors.New("error while marshalling")
	}

	userlib.DatastoreSet(uuid, marshalled_container)
	return nil
}

func get_from_datastore(uuid uuid.UUID,
	hmac []byte,
	symm_key []byte) (obj interface{}, err error) {

	bytes, empty := userlib.DatastoreGet(uuid)
	if !empty {
		// print the UUID
		fmt.Println("UUID:", uuid.String())
		return nil, errors.New("No entry found with UUID in Datastore.")
	}

	// unmarshalling the content
	var container File_container
	err = json.Unmarshal(bytes, &container)
	if err != nil {
		return nil, errors.New("Error when unmarshalling")
	}

	//cheking the HMACs are the same
	is_same, err_hmac := is_hmac_match(container.Cypher_text, container.Hmac, hmac)
	if err_hmac != nil {
		return nil, err_hmac
	}
	if !is_same {
		// print hmacs line by line
		fmt.Println("HMACs are different\n===\nContainer")
		fmt.Println(container.Hmac)
		fmt.Println("===\nHMAC")
		fmt.Println(hmac)
		return nil, errors.New("HMACs do not match")
	}

	data_bytes := userlib.SymDec(symm_key, container.Cypher_text)

	// unmarshalling the data
	err = json.Unmarshal(data_bytes, &obj)
	if err != nil {
		return nil, errors.New("Error when unmarshalling")
	}

	return obj, nil
}

func is_hmac_match(ciphertext []byte,
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

func (userdata *User) get_file(filename string) (file_obj *File, err error) {
	// must be owner of the file to get the file struct
	// since only owner has access to the file struct

	// the user must be the owner of the file
	if !userdata.is_owner(filename) {
		return nil, errors.New("User is not the owner of the file and cannot get the file struct")
	}

	// if the file is not in the user's filespace, then we cannot get the file
	if !userdata.is_file_in_user_filespace(filename) {
		return nil, errors.New("This file does not exist, or the user is not the owner of the file, or the user has not been invited to the file")
	}

	// get the file from the datastore
	file_bytes, err := get_from_datastore(userdata.files[filename], userdata.hmac_key, userdata.symm_key)

	return file_obj, nil
}

// TODO
func (userdata *User) get_sentinel(filename string) (file_sentinel File_sentinel, err error) {
	// can be owner or user shared to the file, but the paths are different

	if userdata.is_owner(filename) {
		// get the file from the datastore
		file_location := userdata.files[filename]
		file_bytes, err := get_from_datastore(file_location, userdata.hmac_key, userdata.symm_key)
		if err != nil {
			return nil, errors.New("Error when getting file from datastore")
		}
		return file_bytes.(*File), nil

	} else {

		// get keys
		file_uuid, hmac_key, symm_key := userdata.get_file_keys()

		// if not owner, then must get sentinel from the invites
		invite_uuid, err_invite := uuid.FromBytes(file_uuid)
		if err_invite != nil {
			return nil, nil, errors.New("Cannot convert bytes to invite UUID")
		}

		invite_bytes, err := get_from_datastore(invite_uuid, hmac_key, symm_key)
		if err != nil {
			return nil, err
		}

		file, ok := invite_bytes.(Invite)
		if !ok {
			return nil, nil, errors.New("Cannot convert invite bytes to Invite")
		}

		sentinel_bytes, err := get_from_datastore(file.Head, file.Hmac, file.Key)
		if err != nil {
			return nil, nil, err
		}
		sentinel, ok := sentinel_bytes.(File_sentinel)
		if !ok {
			return nil, nil, errors.New("Cannot convert sentinel bytes to File_sentinel")
		}

		err_unmar_sentinel := json.Unmarshal(sentinel_bytes, &sentinel)
		if err_unmar_sentinel != nil {
			return nil, nil, errors.New("Error while unmarshalling sentinel")
		}
	}

	return sentinel, nil
}

func (userdata *User) get_file_keys(uuid byte[], hmac_key byte[], symm_key byte[]) {
	// regenerating keys
	key, key_err := userlib.HashKDF(userdata.master_key, []byte(filename))
	if key_err != nil {
		return nil, key_err
	}

	uuid, hmac_key, symm_key := key[:16], key[16:32], key[48:64]
	return uuid, hmac_key, symm_key
}

// TODO
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	if !userdata.is_file_in_user_filespace(filename) {
		file := File{
			Sentinel_uuid: uuid.New(),
			Owner:         userdata.Username,
			Editors:       make(map[string]uuid.UUID),
			Hmac:          userlib.RandomBytes(16),
			Key:           userlib.RandomBytes(16), // need to first generate this key by the owner
			Iv:            userlib.RandomBytes(16),
			Editors_uuid:  uuid.New(),
			Editors_hmac:  userlib.RandomBytes(16),
			Editors_key:   userlib.RandomBytes(16),
			Editors_iv:    userlib.RandomBytes(16),
		}

		// Generating & Saving file to datastore and relating that file to user
		file_obj_bytes, err := json.Marshal(file)
		if err != nil {
			return errors.New("Error when marshalling")
		}

		file_meta_uuid := uuid.New()
		userdata.files[filename] = file_meta_uuid // adding file metadata (file struct) to user's files
		err_save := save_to_datastore(file_meta_uuid, file_obj_bytes, file.Hmac, file.Key, file.Iv)
		if err_save != nil {
			return err_save
		}

		// Creating & Saving sentinel to datastore
		file_sentinel := File_sentinel{Head: uuid.New()}
		file_sentinel_bytes, err := json.Marshal(file_sentinel)
		if err != nil {
			return errors.New("Error when marshalling")
		}
		err_save = save_to_datastore(file.Sentinel_uuid, file_sentinel_bytes, file.Hmac, file.Key, file.Iv)
		if err_save != nil {
			return err_save
		}

		// Creating & Saving "File Node" to datastore, adding to sentinel head
		current_node := File_node{Data: content, Next: uuid.Nil}
		file_n_bytes, err := json.Marshal(current_node)
		if err != nil {
			return errors.New("Error when marshalling")
		}
		err_save_node := save_to_datastore(file_sentinel.Head, file_n_bytes, file.Hmac, file.Key, file.Iv)
		if err_save_node != nil {
			return err_save_node
		}

		// Update end of sentinel to point to the starting node
		file_sentinel.End = current_node.Next

		// Finally, creating Editors (only when the file did not exist before) for sharing with the owner as the root
		root_node := Node{id: userdata.Username, children: nil}
		editors := Editors{editors_tree: root_node}
		save_to_datastore(file.Editors_uuid, editors, file.Editors_hmac, file.Editors_key, file.Editors_iv)

		

		return nil
	}

	// if file exists, overwrite the file
	file_meta, err := userdata.get_file(filename)
	if err != nil {
		return err
	}
	sentinel, err := userdata.get_sentinel(filename)
	if err != nil {
		return err
	}

	node := File_node{Next: sentinel.Head, Data: content}
	node_bytes, err_mar := json.Marshal(node)
	if err_mar != nil {
		return err_mar
	}

	node_err := save_to_datastore(sentinel.Head, node_bytes, file_meta.Hmac, file_meta.Key, file_meta.Iv)
	if node_err != nil {
		return node_err
	}

	// update and save sentinel

	sentinel.End = sentinel.Head
	sentinel_bytes, err_mar := json.Marshal(sentinel)
	if err_mar != nil {
		return err_mar
	}
	err_saving_sentinel := save_to_datastore(file_meta.Sentinel_uuid, sentinel_bytes, file_meta.Hmac, file_meta.Key, file_meta.Iv)
	if err_saving_sentinel != nil {
		return err_saving_sentinel
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	file, sentinel, err_get_file := get_sentinel(userdata.master_key, filename)
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
	file, sentinel, err_get_file := get_sentinel(userdata.master_key, filename)
	if err_get_file != nil {
		return nil, err_get_file
	}

	// getting "current node" from data store & unmarshalling it
	var curr_node File_node
	curr_node_bytes, err_curr_node_bytes := get_from_datastore(sentinel.Head, file.Hmac, file.Key)
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
		curr_node_bytes, traverse_err := get_from_datastore(curr_node.Next, file.Hmac, file.Key) // both sentinel and the linked list blobs are encrypted with the file keys
		if traverse_err != nil {
			return nil, traverse_err
		}

		err_mar := json.Unmarshal(curr_node_bytes, curr_node)
		if err_mar != nil {
			return nil, err_mar
		}

		file_bytes = append(file_bytes, curr_node.Data...)
	}

	return file_bytes, nil
}

// TODO among other things, encrypt the invitation with the recipient's public key
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// hash_editor = recipientUsername
	// hash_editor := hex.EncodeToString(userlib.Hash([]byte(recipientUsername)))

	file, sentinel, err_get_file := get_sentinel(userdata.master_key, filename)
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

		err_saving_file := save_to_datastore(sentinel.Head, file_bytes, file.Hmac, file.Key, file.Iv)
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

		return userdata.invites_map[filename], save_to_datastore(sentinel.Head, file_bytes, file.Hmac, file.Key, file.Iv)
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

	// Does senderUsername exist? Checking this via getting the public key of the sender
	public_key, pk_exist := userlib.KeystoreGet(senderUsername + "public-key")
	if !pk_exist {
		return errors.New("Cannot get the public key of senderUsername")
	}

	// Getting the signature from the sender
	signature, sign_exist := userlib.KeystoreGet(senderUsername + "key-verify")
	if !sign_exist {
		return errors.New("Cannot get the digitial signature of the sender")
	}

	// (1.3) Getting the cyphertext from invitationPtr
	cypher_text, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Cannot get invitation from Datastore")
	}

	// (1.4) Verify the signature
	valid_signature := userlib.DSVerify(public_key, cypher_text, signature.PubKey.N.Bytes())
	if valid_signature != nil {
		return errors.New("Cannot verify the sender is the real sender of the invitation")
	}
	// (2) Decrypt the cypher text to get file location
	invite_container, err := userlib.PKEDec(userdata.private_key, cypher_text)
	if err != nil {
		return nil
	}

	// (3) Unmarshal the invite
	var invitation Invite
	err = json.Unmarshal(invite_container, &invitation)
	if err != nil {
		return errors.New("Cannot numarshal the invitation")
	}

	// (4) Verify that the invitation is for the correct file
	if invitation.File != filename {
		return errors.New("The invitation is not for the correct file")
	}

	// (6) Get the file location
	file_location := invitation.File_uuid

	// (7) Unmarshal file_location to get uuid.UUID
	var file_uuid uuid.UUID
	err_marshalling := json.Unmarshal(file_location, &file_uuid)
	if err_marshalling != nil {
		return nil
	}

	// (8) Add "invite"	 to "invites_map"
	userdata.invites_map[filename] = file_uuid

	// add ourselves to the Editors list

	// get the editors list from the invite struct

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

	// TODO: rehash the file with a new key

	// (7) Update the file location in the user's file map
	userdata.files[filename] = new_file_location

	// TODO (8) Update the file's Editor map with new location for every user except the recipient
	for user, _ := range file.Editors {
		if user != recipientUsername {
			file.Editors[user] = new_file_location
		}
	}
	// (9) Remove recipient from file's Editor map
	delete(file.Editors, recipientUsername)

	return nil
}
