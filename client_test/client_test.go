package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
	// RunSpecs(t, "Advanced Tests")

}

func AdvancedTests(t *testing.T) {
	RegisterFailHandler(Fail)
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var harcho *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	harchoFile := "harchoFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			harcho, err = client.InitUser("harcho", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for harcho for file %s, and harcho accepting invite under name %s.", bobFile, harchoFile)
			invite, err = bob.CreateInvitation(bobFile, "harcho")
			Expect(err).To(BeNil())

			err = harcho.AcceptInvitation("bob", invite, harchoFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that harcho can load the file.")
			data, err = harcho.LoadFile(harchoFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/harcho lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = harcho.LoadFile(harchoFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = harcho.AppendToFile(harchoFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: Testing Revoke Functionality with COrUpteD file", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			harcho, err = client.InitUser("harcho", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for harcho for file %s, and Charlie accepting invite under name %s.", bobFile, harchoFile)
			invite, err = bob.CreateInvitation(bobFile, "harcho")
			Expect(err).To(BeNil())

			err = harcho.AcceptInvitation("bob", invite, harchoFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that harcho can load the file.")
			data, err = harcho.LoadFile(harchoFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile+"CoRruPTED")
			err = alice.RevokeAccess(aliceFile+"CoRruPTED", "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob still has access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
		})

		Specify("Testing Revocation: Datastore Tampering", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			tamperingArray := []byte{'1', '2', '3', '4'}

			for key, _ := range userlib.DatastoreGetMap() {
				userlib.DatastoreSet(key, tamperingArray)

			}
			userlib.DebugMsg("Checking that harcho cannot load the file.")
			data, err = harcho.LoadFile(harchoFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice should not be able to revoke Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Alice cannot still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Checking that Bob/harcho lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = harcho.LoadFile(harchoFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = harcho.AppendToFile(harchoFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		// Specify("Testing if Revocation: Keystore Tampering", func() {
		// 	userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
		// 	aliceDesktop, err = client.InitUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	bob, err = client.InitUser("bob", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	harcho, err = client.InitUser("harcho", "")
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Getting second instance of Harcho")
		// 	harcho, err = client.GetUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
		// 	aliceLaptop, err = client.GetUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
		// 	err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("aliceLaptop creating invite for Bob.")
		// 	invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
		// 	err = bob.AcceptInvitation("alice", invite, bobFile)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
		// 	err = bob.AppendToFile(bobFile, []byte(contentTwo))
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
		// 	err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
		// 	data, err := aliceDesktop.LoadFile(aliceFile)
		// 	Expect(err).To(BeNil())
		// 	Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

		// 	userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
		// 	data, err = aliceLaptop.LoadFile(aliceFile)
		// 	Expect(err).To(BeNil())
		// 	Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

		// 	userlib.DebugMsg("Checking that Bob sees expected file data.")
		// 	data, err = bob.LoadFile(bobFile)
		// 	Expect(err).To(BeNil())
		// 	Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

		// 	userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
		// 	alicePhone, err = client.GetUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
		// 	data, err = alicePhone.LoadFile(aliceFile)
		// 	Expect(err).To(BeNil())
		// 	Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

		// 	userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
		// 	_, err = aliceDesktop.CreateInvitation(aliceFile, "bob")
		// 	Expect(err).To(BeNil())

		// 	// harcho does not have file yet
		// 	err = harcho.AcceptInvitation("bob", invite, harchoFile)
		// 	Expect(err).ToNot(BeNil())

		// 	// // TRICK invite harcho along
		// 	// userlib.DebugMsg("bob sharing non existent file to harcho")
		// 	// invite, err = bob.CreateInvitation(aliceFile, "harcho")
		// 	// Expect(err).ToNot(BeNil())

		// 	// invite harcho along
		// 	userlib.DebugMsg("bob sharing EXISTENT file to harcho")
		// 	invite, err = bob.CreateInvitation(bobFile, "harcho")
		// 	Expect(err).To(BeNil())

		// 	err = harcho.AcceptInvitation("bob", invite, harchoFile)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Checking that harcho can load the file.")
		// 	data, err = harcho.LoadFile(harchoFile)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
		// 	err = alice.RevokeAccess(aliceFile, "bob")
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Checking that Alice can still load the file.")
		// 	data, err = alice.LoadFile(aliceFile)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Checking that Bob/harcho lost access to the file.")
		// 	_, err = bob.LoadFile(bobFile)
		// 	Expect(err).ToNot(BeNil())

		// 	_, err = harcho.LoadFile(harchoFile)
		// 	Expect(err).ToNot(BeNil())

		// 	userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
		// 	err = bob.AppendToFile(bobFile, []byte(contentTwo))
		// 	Expect(err).ToNot(BeNil())

		// 	userlib.DebugMsg("Checking that HARCHO the revoked users cannot append to the file.")
		// 	err = harcho.AppendToFile(harchoFile, []byte(contentThree))
		// 	Expect(err).ToNot(BeNil())

		// 	userlib.DebugMsg("Checking that HARCHO the revoked users cannot append to the file.")
		// 	err = harcho.AppendToFile(harchoFile, []byte(contentTwo))
		// 	Expect(err).ToNot(BeNil())

		// 	// but alice still can
		// 	userlib.DebugMsg("Checking that Alice can still load the file.")
		// 	data, err = alice.LoadFile(aliceFile)
		// 	Expect(err).To(BeNil())
		// })

		Specify("Arbitrary usernames length test.", func() {
			userlib.DebugMsg("Initializing user zero.")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())

			// create user with same username FAILLLL
			userlib.DebugMsg("Initializing user.")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			var string1 string
			for i := 0; i < 66; i++ {
				string1 += "7"
			}
			userlib.DebugMsg("Initializing user.")
			alice, err = client.InitUser(string1, defaultPassword)
			Expect(err).To(BeNil())

			var string2 string
			for i := 0; i < 400; i++ {
				string2 += "C"
			}
			userlib.DebugMsg("Initializing user.")
			alice, err = client.InitUser(string2, defaultPassword)
			Expect(err).To(BeNil())

			// share public file with bob
			userlib.DebugMsg("alice sharing public file to bob")
			err = alice.StoreFile("public.txt", []byte("public"))
			Expect(err).To(BeNil())

			// share the file with bob
			userlib.DebugMsg("alice sharing file to bob")
			invite, err := alice.CreateInvitation("public.txt", "bob")
			Expect(err).To(BeNil())

			// bob accepts invite
			userlib.DebugMsg("bob accepting invite")
			err = bob.AcceptInvitation(alice.Username, invite, "bob.txt")
			Expect(err).To(BeNil())

			/////////////////////////

			// Test case logic
			// Store a file with sensitive content
			content := []byte("This is a confidential message")
			err = alice.StoreFile("confidential.txt", content)
			Expect(err).To(BeNil())

			// Load the file and check if the content is decrypted correctly
			loadedContent, err := alice.LoadFile("confidential.txt")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(content))

			// Test case logic
			// Store a file with sensitive content
			content = []byte("This is a confidential message")
			err = alice.StoreFile("confidential.txt", content)
			Expect(err).To(BeNil())

			// Bob should not be able to access the file
			loadedContent, err = bob.LoadFile("confidential.txt")
			Expect(err).To(HaveOccurred())
			Expect(loadedContent).To(BeNil())

			// Test case logic
			// Store a file
			content = []byte("This is a file")
			err = alice.StoreFile("file.txt", content)
			Expect(err).To(BeNil())

			// Load the file and modify the content
			modifiedContent, err := alice.LoadFile("file.txt")
			Expect(err).To(BeNil())
			modifiedContent[0] = 'X'

			modifiedContent[9] = byte('X')

			// Load the file again and check if the content is different
			loadedContent, err = alice.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(loadedContent).NotTo(Equal(modifiedContent))

			// Test case logic
			// Store a file with initial content
			content = []byte("Original content")
			err = alice.StoreFile("file1.txt", content)
			Expect(err).To(BeNil())

			// Append to the file
			appendedContent := []byte("Appended content")
			err = alice.AppendToFile("file1.txt", appendedContent)
			Expect(err).To(BeNil())

			// Load the file and check if the content reflects the appended data
			loadedContent, err = alice.LoadFile("file1.txt")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(append(content, appendedContent...)))

			// Store a different file with its own content
			otherContent := []byte("Other content")
			err = alice.StoreFile("file2.txt", otherContent)
			Expect(err).To(BeNil())

			// Append to the different file
			otherAppendedContent := []byte("Other appended content")
			err = alice.AppendToFile("file2.txt", otherAppendedContent)
			Expect(err).To(BeNil())

			// Load the different file and check if the content reflects the appended data
			otherLoadedContent, err := alice.LoadFile("file2.txt")
			Expect(err).To(BeNil())
			Expect(otherLoadedContent).To(Equal(append(otherContent, otherAppendedContent...)))

			// Test case logic
			// Store a file
			content = []byte("Original content")
			err = alice.StoreFile("file.txt", content)
			Expect(err).To(BeNil())

			// Load the file and modify the content
			modifiedContent, err = alice.LoadFile("file.txt")
			Expect(err).To(BeNil())
			modifiedContent[0] = 'M'

			// Load the file again and check if the content is different
			loadedContent, err = alice.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(loadedContent).NotTo(Equal(modifiedContent))

			// Store a file with initial content
			content = []byte("Original content")
			err = alice.StoreFile("file.txt", content)
			Expect(err).To(BeNil())

			// Randomly modify the content in the datastore
			for i := 0; i < 1000; i++ {
				modifiedContent = make([]byte, len(content))
				copy(modifiedContent, content)

				// Randomly modify a byte in the content
				randomIndex := 2
				modifiedContent[randomIndex] = 'X'

				// Store the modified content back to the file
				err := alice.StoreFile("file.txt", modifiedContent)
				Expect(err).To(BeNil())
			}

			// Load the file and check if the content is the last modified version
			loadedContent, err = alice.LoadFile("file.txt")
			Expect(err).To(BeNil())

			// Verify that the loaded content is the last modified version
			Expect(loadedContent).To(Equal(modifiedContent))

			// Perform revocations on the file that recipient does not have
			err = alice.RevokeAccess("file.txt", bob.Username)
			Expect(err).ToNot(BeNil())

			// Perform revocations on the file that recipient does have
			err = alice.RevokeAccess("public.txt", bob.Username)
			Expect(err).To(BeNil())

			// Attempt to load the file with Bob, expecting an error
			_, err = bob.LoadFile("file.txt")
			Expect(err).ToNot(BeNil())

			// verify that alice still has access to the file
			loadedContent, err = alice.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(modifiedContent))

			// Store a file with initial content
			content = []byte("Original content")
			err = alice.StoreFile("file.txt", content)
			Expect(err).To(BeNil())

			// Randomly modify the content in the datastore
			for i := 0; i < 10; i++ {
				modifiedContent = make([]byte, len(content))
				copy(modifiedContent, content)

				// Randomly modify a byte in the content
				randomIndex := 2
				modifiedContent[randomIndex] = 'X'

				// Store the modified content back to the file
				err := alice.StoreFile("file.txt", modifiedContent)
				Expect(err).To(BeNil())
			}

			// Load the file and check if the content is the last modified version
			loadedContent, err = alice.LoadFile("file.txt")
			Expect(err).To(BeNil())
			// Verify that the loaded content is the last modified version
			Expect(loadedContent).To(Equal(modifiedContent))

			// userlib.DebugMsg("Initializing user Alice")
			// alice, err = client.InitUser("alice", defaultPassword)
			// Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

		})

		Specify("Accepting Before invite ", func() {
			userlib.DebugMsg("Initializing users Alice")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles")
			bob, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop creating invite for charles.")
			invite, err := aliceDesktop.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
		})

		Specify("Create/Accept Invite Functionality with multiple users ", func() {
			userlib.DebugMsg("Initializing users Alice")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("bob storing file %s with content: %s", bobFile, contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop creating invite for Bob.")
			invite, err := aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())
		})

	})

})
