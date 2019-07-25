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

type AttributeType int

const (
	_ AttributeType = iota
	// Attributes at command level
	SetAttrProtocol    //  1: Protocol version
	SetAttrSetName     //  2: Name of the set
	SetAttrTypeName    //  3: Typename
	SetAttrRevision    //  4: Settype revision
	SetAttrFamily      //  5: Settype family
	SetAttrFlags       //  6: Flags at command level
	SetAttrData        //  7: Nested attributes
	SetAttrADT         //  8: Multiple data containers
	SetAttrLineNo      //  9: Restore lineno
	SetAttrProtocolMin // 10: Minimal supported version number
	SetAttrMax
)

const (
	_ AttributeType = iota
	// CADT specific attributes
	SetDataAttrIP         //  1:
	SetDataAttrIPTo       //  2:
	SetDataAttrCidr       //  3:
	SetDataAttrPort       //  4:
	SetDataAttrPortTo     //  5:
	SetDataAttrTimeout    //  6:
	SetDataAttrProto      //  7:
	SetDataAttrCadtFlags  //  8:
	SetDataAttrCadtLineNo //  9:
	SetDataAttrMark       // 10:
	SetDataAttrMarkMask   // 11:
	SetDataAttrCadtMax    = 16
)

const (
	_ AttributeType = iota + SetDataAttrCadtMax
	// Create-only specific attributes.
	SetDataAttrGc       // 17:
	SetDataAttrHashSize // 18:
	SetDataAttrMaxElem  // 19:
	SetDataAttrNetmask  // 20:
	SetDataAttrProbes   // 21:
	SetDataAttrResize   // 22:
	SetDataAttrSize     // 23:

	// Kernel-only
	SetDataAttrElements   // 24:
	SetDataAttrReferences // 25:
	SetDataAttrMemSize    // 26:
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
