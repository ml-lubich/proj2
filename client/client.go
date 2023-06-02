package client

// CS 161 Project 2

import (
	"encoding/json"
	"fmt"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// ====================================================================================================
// Structs
// ====================================================================================================

type AccessToken struct {
	// Provides all three components to access an object in the datastore.
	// 1. uuid of where the
	// 2. hmac of the object
	// 3. string
	// Note: it is only secure to verify / sign the encrypted data first, then decrypt the data
	// Note 2: it is only secure to encrypt the data first, then verify / sign the data
	U  uuid.UUID
	HK []byte
	EK []byte
}

type Share struct {
	Owner      string
	Recipient  string
	FileHeader AccessToken
}

type Container struct {
	O []byte
	H []byte
}

type FileMetadata struct {
	Owner         string
	Header        AccessToken
	SharedHeaders map[string]AccessToken
}

// used for sharing files with others (another layer of abstraction to ensure security)
type FileHeader struct {
	SentinelAccess AccessToken
}

type FileSentinel struct {
	Start AccessToken
	End   AccessToken
}

type FileBlob struct {
	HasNext bool
	Next    AccessToken
	Content AccessToken
}

type FileContent struct {
	Content []byte
}

type User struct {
	Username   string
	Password   string
	PrivateKey userlib.PrivateKeyType
	SignKey    userlib.DSSignKey
}

// =================================================================================================
// Authentication Helpers
// =================================================================================================

func getUUID(deterministicData []byte) uuid.UUID {
	// get deterministic uuid from string
	hash := userlib.Hash(deterministicData)
	uuid := uuid.NewSHA1(uuid.Nil, hash)
	return uuid
}

func getSalt(username string) ([]byte, error) {
	uuidSalt := getUUID([]byte(username + "salt"))
	salt, ok := userlib.DatastoreGet(uuidSalt)
	if !ok {
		return nil, errors.New("Error when retrieving user salt.")
	}
	return salt, nil
}

func getPasswordHash(username string) ([]byte, error) {
	uuidPasswordHash := getUUID([]byte(username + "passwordHash"))
	passwordHash, ok := userlib.DatastoreGet(uuidPasswordHash)
	if !ok {
		return nil, errors.New("Error when retrieving user password hash.")
	}
	return passwordHash, nil
}

func getPasswordSalted(username string, password string) ([]byte, error) {
	salt, err := getSalt(username)
	if err != nil {
		return nil, err
	}
	passwordSalted := userlib.Argon2Key([]byte(password), salt, 16)
	return passwordSalted, nil
}

func authenticateUser(username string, passwordSalted []byte) (isAuthenticated bool, err error) {
	userPasswordHashStored, err := getPasswordHash(username)
	if err != nil {
		return false, errors.New("Error when retrieving user password hash.")
	}
	userPasswordHash := userlib.Hash(passwordSalted)
	isAuthenticated = userlib.HMACEqual(userPasswordHash, userPasswordHashStored)
	return isAuthenticated, nil
}

func checkHmac(containerObject []byte, containerHmac []byte, hmacKey []byte) (ok bool, error error) {
	calculatedHmac, err := userlib.HMACEval(hmacKey, containerObject)
	if err != nil {
		return false, err
	}
	if !userlib.HMACEqual(calculatedHmac, containerHmac) {
		return false, errors.New(fmt.Sprintf("HMACs do not match.\nHMAC:\"%s\"ContainerHMAC:\"%s\"", calculatedHmac, containerHmac))
	}
	return true, nil
}

func getRandomAccessToken() (accessToken AccessToken) {
	randomUuid := uuid.New()
	randomHmacKey := userlib.RandomBytes(16)
	randomEncryptionKey := userlib.RandomBytes(16)
	accessToken = AccessToken{
		U:  randomUuid,
		HK: randomHmacKey,
		EK: randomEncryptionKey,
	}
	return accessToken
}

// func getFileId(user *User, filename string) (fileId []byte) {
// 	// hash the filename with respect to the user's symmetric key
// 	passwordSalted, err := getPasswordSalted(user.Username, user.Password)
// 	if err != nil {
// 		return nil
// 	}
// 	fileIdEncryptionKey, err := userlib.HashKDF(passwordSalted, []byte(filename))
// 	if err != nil {
// 		return nil
// 	}
// 	fileIdEncryptionKey = fileIdEncryptionKey[:16]
// 	iv := userlib.RandomBytes(16)
// 	fileId = userlib.SymEnc(fileIdEncryptionKey, iv, []byte(filename))
// 	return fileId
// }

func getFileMetadataUuid(passwordSalted []byte, filename string) (fileMetadataUuid uuid.UUID) {
	// get the deterministic file UUID from the filename symmterically encrypted with the user's symmetric key
	// generate deterministic file uuid (file ID)
	// hash the filename to make it one length
	filenameHash := userlib.Hash([]byte(filename))
	filenameEncrypted := userlib.SymDec(passwordSalted, filenameHash)
	fileMetadataUuid = getUUID(filenameEncrypted)
	return fileMetadataUuid
}

func getFileMetadataHmacKey(passwordSalted []byte, filename string) (fileHmacKey []byte, err error) {
	// get the deterministic file HMAC key from the filename derived from HashKDF of passwordSalted
	filenameHash := userlib.Hash([]byte(filename + "hmac"))
	fileHmacKey, err = userlib.HashKDF(passwordSalted, filenameHash)
	fileHmacKey = fileHmacKey[:16]
	if err != nil {
		return nil, err
	}
	return fileHmacKey, nil
}

func getFileMetadataEncryptionKey(passwordSalted []byte, filename string) (fileEncryptionKey []byte, err error) {
	// get the deterministic file symmetric encryption key from the filename derived from HashKDF of passwordSalted
	filenameHash := userlib.Hash([]byte(filename + "encryption"))
	fileEncryptionKey, err = userlib.HashKDF(passwordSalted, filenameHash)
	fileEncryptionKey = fileEncryptionKey[:16]
	if err != nil {
		return nil, err
	}
	return fileEncryptionKey, nil
}

// =================================================================================================
// Authentication Helpers
// =================================================================================================

// =================================================================================================
// Datastore Helpers
// =================================================================================================

func getObjectFromDatastore(accessToken AccessToken) ([]byte, error) {
	objectMarshalled, ok := userlib.DatastoreGet(accessToken.U)
	if !ok {
		return nil, errors.New(fmt.Sprintf("No data found at UUID: \"%v\"", accessToken.U))
	}
	// unmarshalling the content
	var container Container
	err := json.Unmarshal(objectMarshalled, &container)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error when unmarshalling this container with UUID: \"%v\"", accessToken.U))
	}
	// in order to ensure security, verify then decrypt
	// cheking the HMACs are the same
	ok, err = checkHmac(container.O, container.H, accessToken.HK)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, err
	}
	// decrypt the content
	object := userlib.SymDec(accessToken.EK, container.O)
	return object, nil
}

func setObjectToDatastore(object interface{}, accessToken AccessToken) (err error) {
	// marshal the object
	objectMarshalled, err := json.Marshal(object)
	if err != nil {
		return errors.New("Error when marshalling the object.")
	}
	// encrypt and sign the object
	iv := userlib.RandomBytes(16)
	objectEncrypted := userlib.SymEnc(accessToken.EK, iv, objectMarshalled)
	containerHmac, err := userlib.HMACEval(accessToken.HK, objectEncrypted)
	if err != nil {
		return err
	}
	// create container
	container := Container{
		O: objectEncrypted,
		H: containerHmac,
	}
	// marshal the container
	bytes, err := json.Marshal(container)
	if err != nil {
		return err
	}
	// set the container in the datastore
	userlib.DatastoreSet(accessToken.U, bytes)
	return nil
}

func deleteObjectFromDatastore(accessToken AccessToken) (err error) {
	userlib.DatastoreDelete(accessToken.U)
	return nil
}

// =================================================================================================
// Datastore Helpers
// =================================================================================================

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New("No username has been entered.")
	}
	_, userExists := userlib.KeystoreGet(username + "publicKey")
	if userExists {
		return nil, errors.New(fmt.Sprintf("The user with username \"%s\" already exists.", username))
	}

	// generate public, private, and digital signature keys
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	signKey, verifyKey, err := userlib.DSKeyGen()

	// save public key and digital signature verify key to datastore
	err = userlib.KeystoreSet(username+"publicKey", publicKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"verifyKey", verifyKey)
	if err != nil {
		return nil, err
	}
	user := User{
		Username:   username,
		Password:   password,
		PrivateKey: privateKey,
		SignKey:    signKey,
	}

	// encrypt and HMAC the user
	salt := userlib.RandomBytes(512)
	passwordSalted := userlib.Argon2Key([]byte(password), salt, 16)
	// hashing the salted password since user passwords are not guaranteed to be globally unique
	passwordHash := userlib.Hash(passwordSalted)
	// encrypt and hmac the user struct
	if err != nil {
		return nil, err
	}
	userEncryptionKey, err := userlib.HashKDF(passwordSalted, []byte("encryption"))
	userEncryptionKey = userEncryptionKey[:16]
	if err != nil {
		return nil, err
	}
	userUuid := getUUID([]byte(username + "user"))
	userHmacKey, err := userlib.HashKDF(passwordSalted, []byte("hmac"))
	userHmacKey = userHmacKey[:16]
	if err != nil {
		return nil, err
	}
	userAccessToken := AccessToken{
		U:  userUuid,
		HK: userHmacKey,
		EK: userEncryptionKey,
	}
	// save the user to datastore
	err = setObjectToDatastore(user, userAccessToken)
	// store the password hash in datastore
	uuidPasswordHash := getUUID([]byte(username + "passwordHash"))
	userlib.DatastoreSet(uuidPasswordHash, passwordHash)
	// store salt in datastore
	userlib.DatastoreSet(getUUID([]byte(username+"salt")), salt)
	return &user, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// get user struct from datastore
	// user struct is encrypted with the user's symmetric key (salted password and the msg "encryption")
	// check if user exists in keystore
	_, userExists := userlib.KeystoreGet(username + "publicKey")
	if !userExists {
		return nil, errors.New(fmt.Sprintf("The user with username \"%s\" does not exist.", username))
	}
	// authenticate the user via the password hash
	passwordSalted, err := getPasswordSalted(username, password)
	if err != nil {
		return nil, err
	}
	isAuthenticated, err := authenticateUser(username, passwordSalted)
	if err != nil {
		return nil, err
	}
	if !isAuthenticated {
		return nil, errors.New("Error authenticating user: Incorrect password or a malicious action occurred.")
	}
	// user is authenticated, now derive AccessToken to access the user struct
	userUuid := getUUID([]byte(username + "user"))
	userHmacKey, err := userlib.HashKDF(passwordSalted, []byte("hmac"))
	userHmacKey = userHmacKey[:16]
	if err != nil {
		return nil, err
	}
	// derive the symmetric key used to decrypt the user struct
	userEncryptionKey, err := userlib.HashKDF(passwordSalted, []byte("encryption"))
	userEncryptionKey = userEncryptionKey[:16]
	if err != nil {
		return nil, err
	}
	userAccessToken := AccessToken{
		U:  userUuid,
		HK: userHmacKey,
		EK: userEncryptionKey,
	}
	// verify and decrypt the user struct
	userObject, err := getObjectFromDatastore(userAccessToken)
	if err != nil {
		return nil, err
	}
	var userStruct User
	err = json.Unmarshal(userObject, &userStruct)
	if err != nil {
		return nil, errors.New("Error when converting user object to user struct.")
	}
	return &userStruct, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// store file metadata at a location deterministic to the symmetric key encryption of the filename
	// generate access token for file metadata
	passwordSalted, err := getPasswordSalted(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	fileMetadataUuid := getFileMetadataUuid(passwordSalted, filename)
	fileMetadataHmacKey, err := getFileMetadataHmacKey(passwordSalted, filename)
	if err != nil {
		return err
	}
	fileMetadataEncryptionKey, err := getFileMetadataEncryptionKey(passwordSalted, filename)
	if err != nil {
		return err
	}
	fileMetadataAccessToken := AccessToken{
		U:  fileMetadataUuid,
		HK: fileMetadataHmacKey,
		EK: fileMetadataEncryptionKey,
	}

	// generate random access token for file header, file sentinel and file blob
	fileHeaderAccessToken := getRandomAccessToken()
	sentinelAccessToken := getRandomAccessToken()
	fileBlobAccessToken := getRandomAccessToken()

	fileBlobStartAccessToken := fileBlobAccessToken
	fileBlobEndAccessToken := fileBlobAccessToken
	fileContentAccessToken := getRandomAccessToken()

	// create file metadata
	fileMetadata := FileMetadata{
		Owner:         userdata.Username,
		Header:        fileHeaderAccessToken,
		SharedHeaders: map[string]AccessToken{},
	}
	// create file node
	fileBlob := FileBlob{
		HasNext: false,
		Next:    AccessToken{},
		Content: fileContentAccessToken,
	}
	// create file header
	fileHeader := FileHeader{
		SentinelAccess: sentinelAccessToken,
	}
	// create file sentinel
	fileSentinel := FileSentinel{
		Start: fileBlobStartAccessToken,
		End:   fileBlobEndAccessToken,
	}
	// create file content
	fileContent := FileContent{
		Content: content,
	}

	// create or overwrite file metadata stored at file ID in datastore
	err = setObjectToDatastore(fileMetadata, fileMetadataAccessToken)
	if err != nil {
		return err
	}
	// create or overwrite file header stored at random access token in datastore
	err = setObjectToDatastore(fileHeader, fileHeaderAccessToken)
	if err != nil {
		return err
	}
	// create or overwrite file sentinel stored at random access token in datastore
	err = setObjectToDatastore(fileSentinel, sentinelAccessToken)
	if err != nil {
		return err
	}
	// create or overwrite file sentinel stored at random access token in datastore
	err = setObjectToDatastore(fileSentinel, sentinelAccessToken)
	if err != nil {
		return err
	}
	err = setObjectToDatastore(fileBlob, fileBlobAccessToken)
	if err != nil {
		return err
	}
	err = setObjectToDatastore(fileContent, fileContentAccessToken)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// construct access token to file metadata
	passwordSalted, err := getPasswordSalted(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	fileMetadataUuid := getFileMetadataUuid(passwordSalted, filename)
	fileMetadataHmacKey, err := getFileMetadataHmacKey(passwordSalted, filename)
	if err != nil {
		return err
	}
	fileMetadataEncryptionKey, err := getFileMetadataEncryptionKey(passwordSalted, filename)
	if err != nil {
		return err
	}
	fileMetadataAccessToken := AccessToken{
		U:  fileMetadataUuid,
		HK: fileMetadataHmacKey,
		EK: fileMetadataEncryptionKey,
	}
	fileMetadata, err := getObjectFromDatastore(fileMetadataAccessToken)
	if err != nil {
		return err
	}
	var fileMetadataStruct FileMetadata
	err = json.Unmarshal(fileMetadata, &fileMetadataStruct)
	if err != nil {
		return errors.New("Error when converting file metadata object to file metadata struct.")
	}
	// get file header
	fileHeaderAccessToken := fileMetadataStruct.Header
	fileHeader, err := getObjectFromDatastore(fileHeaderAccessToken)
	if err != nil {
		return err
	}
	var fileHeaderStruct FileHeader
	err = json.Unmarshal(fileHeader, &fileHeaderStruct)
	if err != nil {
		return errors.New("Error when converting file header object to file header struct.")
	}
	// get file sentinel
	fileSentinelAccessToken := fileHeaderStruct.SentinelAccess
	fileSentinel, err := getObjectFromDatastore(fileSentinelAccessToken)
	if err != nil {
		return err
	}
	var fileSentinelStruct FileSentinel
	err = json.Unmarshal(fileSentinel, &fileSentinelStruct)
	if err != nil {
		return errors.New("Error when converting file sentinel object to file sentinel struct.")
	}
	// get end file blob
	endFileBlobAccessToken := fileSentinelStruct.End
	endFileBlob, err := getObjectFromDatastore(endFileBlobAccessToken)
	if err != nil {
		return err
	}
	var endFileBlobStruct FileBlob
	err = json.Unmarshal(endFileBlob, &endFileBlobStruct)
	if err != nil {
		return errors.New("Error when converting file blob object to file blob struct.")
	}

	// CREATING FILE DATA
	// generate random access token for new file blob and new file content
	newFileContentAccessToken := getRandomAccessToken()
	newFileBlobAccessToken := getRandomAccessToken()
	// create a new file blob and new file content
	newFileBlob := FileBlob{
		HasNext: false,
		Next:    AccessToken{},
		Content: newFileContentAccessToken,
	}
	newFileContent := FileContent{
		Content: content,
	}

	// mark the previous end file blob to point to the new file blob
	endFileBlobStruct.Next = newFileBlobAccessToken
	// mark the previous end file blob as not the end
	endFileBlobStruct.HasNext = true

	// save the updated old file blob to the linked list
	err = setObjectToDatastore(endFileBlobStruct, endFileBlobAccessToken)
	if err != nil {
		return err
	}

	// save the new file blob to the linked list
	err = setObjectToDatastore(newFileBlob, newFileBlobAccessToken)
	if err != nil {
		return err
	}

	// save the new file content to the linked list
	err = setObjectToDatastore(newFileContent, newFileContentAccessToken)
	if err != nil {
		return err
	}

	// mark the sentinel end to point to the new file blob
	// save the updated sentinel
	fileSentinelStruct.End = newFileBlobAccessToken
	err = setObjectToDatastore(fileSentinelStruct, fileSentinelAccessToken)
	if err != nil {
		return err
	}

	// TRASH CODE
	// go to the end of the linked list and set the linked list has next to false
	// get the end file blob
	endFileBlobAccessToken = fileSentinelStruct.End
	endFileBlob, err = getObjectFromDatastore(endFileBlobAccessToken)
	if err != nil {
		return err
	}
	err = json.Unmarshal(endFileBlob, &endFileBlobStruct)
	if err != nil {
		return errors.New("Error when converting file blob object to file blob struct.")
	}
	endFileBlobStruct.HasNext = false
	// save the updated file blob
	err = setObjectToDatastore(endFileBlobStruct, endFileBlobAccessToken)
	if err != nil {
		return err
	}

	// get the end file content
	endFileContentAccessToken := endFileBlobStruct.Content
	endFileContent, err := getObjectFromDatastore(endFileContentAccessToken)
	if err != nil {
		return err
	}
	var endFileContentStruct FileContent
	err = json.Unmarshal(endFileContent, &endFileContentStruct)
	if err != nil {
		return errors.New("Error when converting file content object to file content struct.")
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// construct access token to file metadata
	passwordSalted, err := getPasswordSalted(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}
	fileMetadataUuid := getFileMetadataUuid(passwordSalted, filename)
	fileMetadataHmacKey, err := getFileMetadataHmacKey(passwordSalted, filename)
	if err != nil {
		return nil, err
	}
	fileMetadataEncryptionKey, err := getFileMetadataEncryptionKey(passwordSalted, filename)
	if err != nil {
		return nil, err
	}
	fileMetadataAccessToken := AccessToken{
		U:  fileMetadataUuid,
		HK: fileMetadataHmacKey,
		EK: fileMetadataEncryptionKey,
	}
	fileMetadata, err := getObjectFromDatastore(fileMetadataAccessToken)
	if err != nil {
		return nil, err
	}
	var fileMetadataStruct FileMetadata
	err = json.Unmarshal(fileMetadata, &fileMetadataStruct)
	if err != nil {
		return nil, errors.New("Error when converting file metadata object to file metadata struct.")
	}

	// get file header
	fileHeaderAccessToken := fileMetadataStruct.Header
	fileHeader, err := getObjectFromDatastore(fileHeaderAccessToken)
	if err != nil {
		return nil, err
	}
	var fileHeaderStruct FileHeader
	err = json.Unmarshal(fileHeader, &fileHeaderStruct)
	if err != nil {
		return nil, errors.New("Error when converting file header object to file header struct.")
	}

	// get file sentinel
	fileSentinelAccessToken := fileHeaderStruct.SentinelAccess
	fileSentinel, err := getObjectFromDatastore(fileSentinelAccessToken)
	if err != nil {
		return nil, err
	}
	var fileSentinelStruct FileSentinel
	err = json.Unmarshal(fileSentinel, &fileSentinelStruct)
	if err != nil {
		return nil, errors.New("Error when converting file sentinel object to file sentinel struct.")
	}

	// ITERATE AND LINKED LIST TO GET FILE CONTENT
	// get first file blob
	fileBlobAccessToken := fileSentinelStruct.Start
	fileBlob, err := getObjectFromDatastore(fileBlobAccessToken)
	if err != nil {
		return nil, err
	}
	var fileBlobStruct FileBlob
	err = json.Unmarshal(fileBlob, &fileBlobStruct)
	if err != nil {
		return nil, errors.New("Error when converting file blob object to file blob struct.")
	}
	fileContentLoaded := []byte{}
	// concatenate file blob contents while iterating through the linked list of file blobs
	for fileBlobStruct.HasNext {
		fileContent, err := getObjectFromDatastore(fileBlobStruct.Content)
		if err != nil {
			return nil, err
		}
		var fileContentStruct FileContent
		err = json.Unmarshal(fileContent, &fileContentStruct)
		if err != nil {
			return nil, errors.New("Error when converting file content object to file content struct.")
		}
		fileContentLoaded = append(fileContentLoaded, fileContentStruct.Content...)

		// get next file blob
		fileBlob, err = getObjectFromDatastore(fileBlobStruct.Next)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(fileBlob, &fileBlobStruct)
		if err != nil {
			return nil, errors.New("Error when converting file blob object to file blob struct.")
		}
	}
	// concatenate the last file blob content
	fileContent, err := getObjectFromDatastore(fileBlobStruct.Content)
	if err != nil {
		return nil, err
	}
	var fileContentStruct FileContent
	err = json.Unmarshal(fileContent, &fileContentStruct)
	if err != nil {
		return nil, errors.New("Error when converting file content object to file content struct.")
	}
	fileContentLoaded = append(fileContentLoaded, fileContentStruct.Content...)

	return fileContentLoaded, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// first case, if we are owner, we create a new encrypted file header,
	// add it to the shared headers of the owner struct, create the invitation containing the access token to this new encrypted file header
	// second case, if we are not owner, we go to our file metadata, get the file header access token and put it in a new shared struct
	// in both cases, we hash the share struct at a location deterministic to the sender username, send the encryption and mac key
	// fill in the owner field with the owner so that the recipient can verify the invitation came from the owner (and subsequent sharers can verify this is the case)

	// lookup if recipient exists
	recipientPublicKey, ok := userlib.KeystoreGet(recipientUsername + "publicKey")
	if !ok {
		return uuid.Nil, errors.New("Recipient does not exist.")
	}

	// get the file metadata access token
	passwordSalted, err := getPasswordSalted(userdata.Username, userdata.Password)
	if err != nil {
		return uuid.Nil, err
	}
	fileMetadataUuid := getFileMetadataUuid(passwordSalted, filename)
	fileMetadataHmacKey, err := getFileMetadataHmacKey(passwordSalted, filename)
	if err != nil {
		return uuid.Nil, err
	}
	fileMetadataEncryptionKey, err := getFileMetadataEncryptionKey(passwordSalted, filename)
	if err != nil {
		return uuid.Nil, err
	}
	fileMetadataAccessToken := AccessToken{
		U:  fileMetadataUuid,
		HK: fileMetadataHmacKey,
		EK: fileMetadataEncryptionKey,
	}
	fileMetadata, err := getObjectFromDatastore(fileMetadataAccessToken)
	if err != nil {
		return uuid.Nil, err
	}
	var fileMetadataStruct FileMetadata
	err = json.Unmarshal(fileMetadata, &fileMetadataStruct)
	if err != nil {
		return uuid.Nil, errors.New("Error when converting file metadata object to file metadata struct.")
	}
	// get the file header access token
	fileHeaderAccessToken := fileMetadataStruct.Header
	fileHeader, err := getObjectFromDatastore(fileHeaderAccessToken)
	if err != nil {
		return uuid.Nil, err
	}
	var fileHeaderStruct FileHeader
	err = json.Unmarshal(fileHeader, &fileHeaderStruct)
	if err != nil {
		return uuid.Nil, errors.New("Error when converting file header object to file header struct.")
	}

	// get the file sentinel access token
	fileSentinelAccessToken := fileHeaderStruct.SentinelAccess

	// first case (we are the owner), make a new file header and the recipient to the shared headers
	if userdata.Username == fileMetadataStruct.Owner {
		// create a new file header
		newFileHeader := FileHeader{
			SentinelAccess: fileSentinelAccessToken,
		}
		fileHeaderAccessToken = getRandomAccessToken()
		err = setObjectToDatastore(newFileHeader, fileHeaderAccessToken)
		if err != nil {
			return uuid.Nil, err
		}
		// update the shared headers of the file metadata with the new file header access token
		// important because we can revoke invitations using this shared header (since the sharing invitation is stored at a determinstic location with respect to the recipient's username and the filename of the shared file)
		fileMetadataStruct.SharedHeaders[recipientUsername] = fileHeaderAccessToken
		// save the updated file metadata struct
		err = setObjectToDatastore(fileMetadataStruct, fileMetadataAccessToken)
	}

	// if sender is not owner, do not do anything (we get the shared header from the file metadata struct, and share that instead in the share struct)

	// COMMON STEPS
	senderUsername := userdata.Username
	shareStructUuid := getUUID([]byte(senderUsername + recipientUsername + "share"))
	shareAccessToken := AccessToken{
		U:  shareStructUuid,
		HK: userlib.RandomBytes(16),
		EK: userlib.RandomBytes(16),
	}
	// create a new shared struct
	shareStruct := Share{
		Owner:      fileMetadataStruct.Owner,
		Recipient:  recipientUsername,
		FileHeader: fileHeaderAccessToken,
	}
	//  save the share struct to datastore
	err = setObjectToDatastore(shareStruct, shareAccessToken)
	if err != nil {
		return uuid.Nil, err
	}
	// SAVE THE SHARE ACCESS TOKEN TO DATASTORE
	// Note: share struct is too large to sign with public key encryption, so we sign the share access token instead to share the keys
	// create the share access token
	// clear the uuid field to save bytes
	shareAccessToken.U = uuid.Nil
	// marshall the share access token
	shareAccessTokenMarshalled, err := json.Marshal(shareAccessToken)
	if err != nil {
		return uuid.Nil, errors.New("Error when converting share struct to share bytes.")
	}

	// encrypt the share access token with the public key of the recipient
	shareStructEncrypted, err := userlib.PKEEnc(recipientPublicKey, shareAccessTokenMarshalled)
	if err != nil {
		return uuid.Nil, err
	}
	// sign the encrypted share access token with the private key of the sender
	signatureShare, err := userlib.DSSign(userdata.SignKey, shareStructEncrypted)
	if err != nil {
		return uuid.Nil, err
	}

	// put the encrypted share access token into a container
	shareAccessTokenContainer := Container{
		O: shareStructEncrypted,
		H: signatureShare,
	}
	// marshall the container
	shareAccessTokenContainerMarshalled, err := json.Marshal(shareAccessTokenContainer)
	if err != nil {
		return uuid.Nil, errors.New("Error when converting share access token container to share access token container bytes.")
	}
	shareUuid := uuid.New()
	userlib.DatastoreSet(shareUuid, shareAccessTokenContainerMarshalled)
	return shareUuid, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// check if the filename exists in the recipients filespace
	passwordSalted, err := getPasswordSalted(userdata.Username, userdata.Password)
	if err != nil {
		return errors.New("Error when getting password salted.")
	}
	// START CHECK IF FILE EXISTS IN THE FILESPACE //////////////////////////////////////////////////////////////////
	fileMetadataUuid := getFileMetadataUuid(passwordSalted, filename)
	// get the file metadata struct using the uuid
	fileHmacKey, err := getFileMetadataHmacKey(passwordSalted, filename)
	// if err != nil {
	// 	return errors.New("ACCEPT INVITATION (FILE EXISTS CHECK): Error when getting file metadata hmac key.")
	// }
	fileEncryptionKey, err := getFileMetadataEncryptionKey(passwordSalted, filename)
	// if err != nil {
	// 	return errors.New("ACCEPT INVITATION (FILE EXISTS CHECK): Error when getting file metadata encryption key.")
	// }
	fileMetadataAccessToken := AccessToken{
		U:  fileMetadataUuid,
		HK: fileHmacKey,
		EK: fileEncryptionKey,
	}
	fileMetadata, err := getObjectFromDatastore(fileMetadataAccessToken)
	// if err != nil {
	// 	userlib.DebugMsg("ACCEPT INVITATION (FILE EXISTS CHECK): Failed to get filemetadata from datastore.")
	// }
	var fileMetadataStruct FileMetadata
	err = json.Unmarshal(fileMetadata, &fileMetadataStruct)
	// if err != nil {
	// 	userlib.DebugMsg("ACCEPT INVITATION (FILE EXISTS CHECK): Error when converting file metadata object to file metadata struct.")
	// }
	// get the file header access token from the shared headers of the file metadata struct
	fileHeaderAccessToken := fileMetadataStruct.SharedHeaders[userdata.Username]
	// get the file header struct using the file header access token
	fileHeader, err := getObjectFromDatastore(fileHeaderAccessToken)
	// if err != nil {
	// 	userlib.DebugMsg("ACCEPT INVITATION (FILE EXISTS CHECK): Error when getting file header struct.")
	// }
	var fileHeaderStruct FileHeader
	err = json.Unmarshal(fileHeader, &fileHeaderStruct)
	// if err != nil {
	// 	userlib.DebugMsg("ACCEPT INVITATION (FILE EXISTS CHECK): Error unmarshalling fileheader.")
	// }
	// get file sentinel (which will determine if this file was revoked or not from the recipient)
	fileSentinelAccessToken := fileHeaderStruct.SentinelAccess
	// get the file sentinel struct
	fileSentinel, err := getObjectFromDatastore(fileSentinelAccessToken)
	// if err != nil {
	// 	userlib.DebugMsg("ACCEPT INVITATION (FILE EXISTS CHECK): Fail to get file sentinel from datastore.")
	// }

	// KILLER DEATHKNELL FOR THE FILE EXISTING IN FILESPACE CHECK
	// we delete the filesentinel struct when we revoke access so if it is still there, then the file still is in the filespace of the recipient
	var fileSentinelStruct FileSentinel
	err = json.Unmarshal(fileSentinel, &fileSentinelStruct)
	if err == nil {
		return errors.New("ERROR: ACCEPT INVITATION (FILE EXISTS CHECK): File exists in the filespace of the recipient.")
	} else {
		userlib.DebugMsg("PASS: ACCEPT INVITATION (FILE EXISTS CHECK): File DOES NOT exist in the filespace of the recipient.")
	}

	// END CHECK IF FILE EXISTS IN THE FILESPACE //////////////////////////////////////////////////////////////////

	// SENT TOKEN RETRIEVAL
	// get the the sent access token
	shareAccessContainer, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Invitation does not exist.")
	}
	var shareAccessContainerStruct Container
	err = json.Unmarshal(shareAccessContainer, &shareAccessContainerStruct)
	if err != nil {
		return errors.New("Error when converting sent access token container bytes to sent access token container struct.")
	}
	// verify the container access token
	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + "verifyKey")
	if !ok {
		return errors.New("Sender does not exist.")
	}
	err = userlib.DSVerify(senderVerifyKey, shareAccessContainerStruct.O, shareAccessContainerStruct.H)
	if err != nil {
		return errors.New("Unable to verify sent access token.")
	}
	// use private key to decrypt the sent access token
	shareAccessDecrypted, err := userlib.PKEDec(userdata.PrivateKey, shareAccessContainerStruct.O)
	if err != nil {
		return errors.New("Unable to decrypt sent access token.")
	}
	// unmarshall the sent access token
	var shareAccessTokenStruct AccessToken
	err = json.Unmarshal(shareAccessDecrypted, &shareAccessTokenStruct)
	if err != nil {
		return errors.New("Error when converting sent access token bytes to sent access token struct.")
	}

	// ACCESSING SHARE STRUCT
	// generate the access token to access the share struct
	recipientUsername := userdata.Username
	shareStructUuid := getUUID([]byte(senderUsername + recipientUsername + "share")) // get deterministic user id
	shareStructAccessToken := AccessToken{
		U:  shareStructUuid,
		HK: shareAccessTokenStruct.HK,
		EK: shareAccessTokenStruct.EK,
	}
	// get the share struct using the share access token
	share, err := getObjectFromDatastore(shareStructAccessToken)
	if err != nil {
		return errors.New("Unable to get the share struct from datastore.")
	}
	var shareStruct Share
	err = json.Unmarshal(share, &shareStruct)
	if err != nil {
		return errors.New("Error when converting share bytes to share struct.")
	}

	// ERROR CHECK: verify that the share points to an actual file (to check if the share has been revoked or not)
	// get the file header access token
	// Assumption: the file sentinel is moved to another location
	fileHeader = []byte{} // clear
	fileHeader, err = getObjectFromDatastore(shareStruct.FileHeader)
	if err != nil {
		return errors.New("INVITATION REVOCATION CHECK: Error when getting file header from datastore.")
	}
	fileHeaderStruct = FileHeader{} // clear
	err = json.Unmarshal(fileHeader, &fileHeaderStruct)
	if err != nil {
		return errors.New("INVITATION REVOCATION CHECK: Error when converting file header bytes to file header struct.")
	}
	fileSentinel = []byte{} // clear
	fileSentinel, err = getObjectFromDatastore(fileHeaderStruct.SentinelAccess)
	if err != nil {
		return errors.New("INVITATION REVOCATION CHECK: Error when getting file sentinel from datastore.")
	}
	fileSentinelStruct = FileSentinel{} // clear
	err = json.Unmarshal(fileSentinel, &fileSentinelStruct)
	if err != nil {
		return errors.New("INVITATION REVOCATION CHECK: Error when converting file sentinel bytes to file sentinel struct.")
	}

	// ADD FILE TO RECIPIENT'S FILESPACE
	// since invitation is valid at this time, add this file to the user's filespace
	// create new file metadata struct that points to the file header
	newFileMetadataUuid := getFileMetadataUuid(passwordSalted, filename)
	newFileHmac, err := getFileMetadataHmacKey(passwordSalted, filename)
	if err != nil {
		return errors.New("Error when getting file metadata hmac key.")
	}
	newFileEncryption, err := getFileMetadataEncryptionKey(passwordSalted, filename)
	if err != nil {
		return errors.New("Error when getting file metadata encryption key.")
	}
	newFileMetadataAccessToken := AccessToken{
		U:  newFileMetadataUuid,
		HK: newFileHmac,
		EK: newFileEncryption,
	}
	// create file metadata
	newFileMetadata := FileMetadata{
		Owner:         shareStruct.Owner,
		Header:        shareStruct.FileHeader,
		SharedHeaders: map[string]AccessToken{},
	}
	// save the new file metadata struct
	setObjectToDatastore(newFileMetadata, newFileMetadataAccessToken)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// only the owner could revoke access
	// move the file sentinel and the file blobs and the file contents to new locations -- this way, any existing sharing invitations would not be valid
	// delete the file sentinel of the old location
	// then remove the user who has had their access revoked, and update all the shared headers with the file sentinel access token

	// check if recipient user exists
	_, ok := userlib.KeystoreGet(recipientUsername + "verifyKey")
	if !ok {
		return errors.New("Recipient user does not exist.")
	}

	// check if the filename exists in the filespace of the caller
	passwordSalted, err := getPasswordSalted(userdata.Username, userdata.Password)
	if err != nil {
		return errors.New("Error when getting password salted.")
	}
	fileMetadataUuid := getFileMetadataUuid(passwordSalted, filename)
	// get the file metadata access token
	fileMetadataHmac, err := getFileMetadataHmacKey(passwordSalted, filename)
	if err != nil {
		return errors.New("Error when getting file metadata hmac key.")
	}
	fileMetadataEncryption, err := getFileMetadataEncryptionKey(passwordSalted, filename)
	if err != nil {
		return errors.New("Error when getting file metadata encryption key.")
	}
	fileMetadataAccessToken := AccessToken{
		U:  fileMetadataUuid,
		HK: fileMetadataHmac,
		EK: fileMetadataEncryption,
	}
	// get the file metadata
	fileMetadata, err := getObjectFromDatastore(fileMetadataAccessToken)
	if err != nil {
		return errors.New("Error when getting file metadata from datastore.")
	}
	var fileMetadataStruct FileMetadata
	err = json.Unmarshal(fileMetadata, &fileMetadataStruct)
	if err != nil {
		return errors.New("Error when converting file metadata bytes to file metadata struct.")
	}
	// check if the recipient is in the shared headers
	_, ok = fileMetadataStruct.SharedHeaders[recipientUsername]
	if !ok {
		return errors.New("Recipient does not have access to the file.")
	}
	// get the file header access token
	fileHeader, err := getObjectFromDatastore(fileMetadataStruct.Header)
	if err != nil {
		return errors.New("Error when getting file header from datastore.")
	}
	var fileHeaderStruct FileHeader
	err = json.Unmarshal(fileHeader, &fileHeaderStruct)
	if err != nil {
		return errors.New("Error when converting file header bytes to file header struct.")
	}
	// get the file sentinel access token
	fileSentinel, err := getObjectFromDatastore(fileHeaderStruct.SentinelAccess)
	if err != nil {
		return errors.New("Error when getting file sentinel from datastore.")
	}
	var fileSentinelStruct FileSentinel
	err = json.Unmarshal(fileSentinel, &fileSentinelStruct)
	if err != nil {
		return errors.New("Error when converting file sentinel bytes to file sentinel struct.")
	}

	// МОVE FILE BLOBS

	// Update the file sentinel start
	// get the start of the sentinel
	fileBlobStartAccessToken := fileSentinelStruct.Start
	// get the start file blob
	fileBlobStart, err := getObjectFromDatastore(fileBlobStartAccessToken)
	if err != nil {
		return errors.New("Error when getting file blob start from datastore.")
	}
	var fileBlobStartStruct FileBlob
	err = json.Unmarshal(fileBlobStart, &fileBlobStartStruct)
	if err != nil {
		return errors.New("Error when converting file blob start bytes to file blob start struct.")
	}
	// move start file blob to a new location
	newFileBlobStartAccessToken := getRandomAccessToken()
	err = setObjectToDatastore(fileBlobStartStruct, newFileBlobStartAccessToken)
	if err != nil {
		return errors.New("Error when setting file blob start to datastore.")
	}
	// update the filesentinel start to point to a new location
	fileSentinelStruct.Start = newFileBlobStartAccessToken

	// loop the file blobs after the start if they exist
	var currFileBlobAccessToken AccessToken
	var currFileBlobMarshalled []byte
	var currFileBlobStruct FileBlob
	if fileBlobStartStruct.HasNext { // if we have more blobs after the start struct in the file sentinel
		currFileBlobAccessToken = fileBlobStartStruct.Next
		// get the currFileBlobStruct
		currFileBlobMarshalled, err = getObjectFromDatastore(currFileBlobAccessToken)
		if err != nil {
			return errors.New("Error when getting curr file blob from datastore.")
		}
		err = json.Unmarshal(currFileBlobMarshalled, &currFileBlobStruct)
		if err != nil {
			return errors.New("Error when converting curr file blob bytes to curr file blob struct.")
		}
		// *s > *s > *s
		// start > a > b > c
		for currFileBlobStruct.HasNext {
			// get the next file blob struct
			nextFileBlob, err := getObjectFromDatastore(currFileBlobStruct.Next)
			if err != nil {
				return errors.New("Error when getting next file blob from datastore.")
			}
			var nextFileBlobStruct FileBlob
			err = json.Unmarshal(nextFileBlob, &nextFileBlobStruct)
			if err != nil {
				return errors.New("Error when converting next file blob bytes to next file blob struct.")
			}
			// we first move the next file blob to a new location
			newNextFileBlobAccessToken := getRandomAccessToken()
			err = setObjectToDatastore(nextFileBlobStruct, newNextFileBlobAccessToken)
			if err != nil {
				return errors.New("Error when setting next file blob to datastore.")
			}
			// update the curr file blob to point to the new location
			currFileBlobStruct.Next = newNextFileBlobAccessToken
			// save the curr file blob struct to the new location
			newCurrFileBlobAccessToken := getRandomAccessToken()
			// save the curr file blob struct
			err = setObjectToDatastore(currFileBlobStruct, newCurrFileBlobAccessToken)
			if err != nil {
				return errors.New("Error when setting curr file blob to datastore.")
			}

			// update next: set the currFileBlobStruct to the next file blob struc
			currFileBlobStruct = nextFileBlobStruct
		}
	}

	// lastly, update the file sentinel to point to the last file blob
	fileSentinelStruct.End = currFileBlobAccessToken

	// save the file sentinel to a new location
	newFileSentinelAccessToken := getRandomAccessToken()
	err = setObjectToDatastore(fileSentinelStruct, newFileSentinelAccessToken)
	if err != nil {
		return errors.New("Error when setting file sentinel to datastore.")
	}

	// UPDATE TRACKING INFO
	// delete the old file sentinel
	err = deleteObjectFromDatastore(fileHeaderStruct.SentinelAccess)

	// point the file header to the new file sentinel
	fileHeaderStruct.SentinelAccess = newFileSentinelAccessToken

	// save the updated file header
	err = setObjectToDatastore(fileHeaderStruct, fileMetadataStruct.Header)
	if err != nil {
		return errors.New("Error when setting file header to datastore.")
	}

	// remove the recipient from the shared headers
	delete(fileMetadataStruct.SharedHeaders, recipientUsername)

	// update all the shared headers to point to the new sentinel
	for _, sharedHeaderAccessToken := range fileMetadataStruct.SharedHeaders {
		// get the shared header
		sharedHeader, err := getObjectFromDatastore(sharedHeaderAccessToken)
		if err != nil {
			return errors.New("Error when getting shared header from datastore.")
		}
		var sharedHeaderStruct FileHeader
		err = json.Unmarshal(sharedHeader, &sharedHeaderStruct)
		if err != nil {
			return errors.New("Error when converting shared header bytes to shared header struct.")
		}
		// point the shared header to the new file sentinel
		sharedHeaderStruct.SentinelAccess = newFileSentinelAccessToken
		// save the updated shared header
		err = setObjectToDatastore(sharedHeaderStruct, sharedHeaderAccessToken)
		if err != nil {
			return errors.New("Error when setting shared header to datastore.")
		}
	}

	// save the updated file metadata
	err = setObjectToDatastore(fileMetadataStruct, fileMetadataAccessToken)
	if err != nil {
		return errors.New("Error when setting file metadata to datastore.")
	}

	return nil
}
