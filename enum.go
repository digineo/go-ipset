package ipset

import (
	"github.com/ti-mo/netfilter"
)

type messageType netfilter.MessageType

const (
	_ messageType = iota
	IPSetCmdProtocol //  1: Return protocol version
	IPSetCmdCreate   //  2: Create a new (empty) set
	IPSetCmdDestroy  //  3: Destroy a (empty) set
	IPSetCmdFlush    //  4: Remove all elements from a set
	IPSetCmdRename   //  5: Rename a set
	IPSetCmdSwap     //  6: Swap two sets
	IPSetCmdList     //  7: List sets
	IPSetCmdSave     //  8: Save sets
	IPSetCmdAdd      //  9: Add an element to a set
	IPSetCmdDel      // 10: Delete an element from a set
	IPSetCmdTest     // 11: Test an element in a set
	IPSetCmdHeader   // 12: Get set header data only
	IPSetCmdType     // 13: Get set type
)

type attributeType int

const (
	_ attributeType = iota
	IPSetAttrProtocol     //  1: Protocol version
	IPSetAttrSetName      //  2: Name of the set
	IPSetAttrTypeName     //  3: Typename
	IPSetAttrRevision     //  4: Settype revision
	IPSetAttrFamily       //  5: Settype family
	IPSetAttrFlags        //  6: Flags at command level
	IPSetAttrData         //  7: Nested attributes
	IPSetAttrADT          //  8: Multiple data containers
	IPSetAttrLineNo       //  9: Restore lineno
	IPSetAttrProtocolMin  // 10: Minimal supported version number

	IPSetAttrSetName2    = IPSetAttrTypeName    // Setname at rename/swap
	IPSetAttrRevisionMin = IPSetAttrProtocolMin // type rev min
)
