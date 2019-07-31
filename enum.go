package ipset

import (
	"github.com/ti-mo/netfilter"
)

const (
	Protocol = 6
)

type messageType netfilter.MessageType

const (
	_ messageType = iota
	// Message types and commands
	CmdProtocol //  1: Return protocol version
	CmdCreate   //  2: Create a new (empty) set
	CmdDestroy  //  3: Destroy a (empty) set
	CmdFlush    //  4: Remove all elements from a set
	CmdRename   //  5: Rename a set
	CmdSwap     //  6: Swap two sets
	CmdList     //  7: List sets
	CmdSave     //  8: Save sets
	CmdAdd      //  9: Add an element to a set
	CmdDel      // 10: Delete an element from a set
	CmdTest     // 11: Test an element in a set
	CmdHeader   // 12: Get set header data only
	CmdType     // 13: Get set type
)

const (
	_ uint16 = iota
	SetAttrIPAddrIPV4
	SetAttrIPAddrIPV6
)

type AttributeType int

const (
	_ AttributeType = iota
	// Attributes at command level
	AttrProtocol    //  1: Protocol version
	AttrSetName     //  2: Name of the set
	AttrTypeName    //  3: Typename
	AttrRevision    //  4: Settype revision
	AttrFamily      //  5: Settype family
	AttrFlags       //  6: Flags at command level
	AttrData        //  7: Nested attributes
	AttrADT         //  8: Multiple data containers
	AttrLineNo      //  9: Restore lineno
	AttrProtocolMin // 10: Minimal supported version number
	AttrMax

	AttrRevisionMin = AttrProtocolMin
	AttrSetName2    = AttrTypeName
)

const (
	_ AttributeType = iota
	// CADT specific attributes
	AttrIP         //  1:
	AttrIPTo       //  2:
	AttrCidr       //  3:
	AttrPort       //  4:
	AttrPortTo     //  5:
	AttrTimeout    //  6:
	AttrProto      //  7:
	AttrCadtFlags  //  8:
	AttrCadtLineNo //  9:
	AttrMark       // 10:
	AttrMarkMask   // 11:
	AttrCadtMax    = 16
)

const (
	_ AttributeType = iota + AttrCadtMax
	// Create-only specific attributes.
	AttrGc       // 17:
	AttrHashSize // 18:
	AttrMaxElem  // 19:
	AttrNetmask  // 20:
	AttrProbes   // 21:
	AttrResize   // 22:
	AttrSize     // 23:

	// Kernel-only
	AttrElements   // 24:
	AttrReferences // 25:
	AttrMemSize    // 26:
)

const (
	_ AttributeType = iota + AttrCadtMax
	// ADT specific attributes
	AttrEther
	AttrName
	AttrNameRef
	AttrIP2
	AttrCidr2
	AttrIP2To
	AttrIface
	AttrBytes
	AttrPackets
	AttrComment
	AttrSkbMark
	AttrSkbPrio
	AttrSkbQueue
)

type CadtFlags uint32

const (
	Before CadtFlags = 1 << iota
	PhysDev
	NoMatch
	WithCounters
	WithComment
	WithForceDdd
	WithSkbInfo
)
