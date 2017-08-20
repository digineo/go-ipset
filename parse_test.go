package ipset

import (
	"encoding/xml"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSomething(t *testing.T) {
	assert := assert.New(t)

	data, _ := ioutil.ReadFile("testdata/list.xml")
	result := ListResult{}

	assert.NoError(xml.Unmarshal(data, &result))
	assert.Len(result.Sets, 1)
	set := result.Sets[0]

	assert.Equal("clients", set.Name)
	assert.Equal("hash:ip", set.Type)

	assert.Equal("inet", set.Header.Family)
	assert.Equal(1024, set.Header.HashSize)
	assert.Equal(65536, set.Header.MaxElem)
	assert.Equal(7200, set.Header.Timeout)
	assert.Equal(304, set.Header.MemSize)
	assert.Equal(1, set.Header.References)
	assert.Equal(2, set.Header.NumEntries)

	assert.Len(set.Members, 2)
	member := set.Members[0]
	assert.Equal("1.2.3.4", member.Elem)
	assert.Equal(23, member.Timeout)
}
