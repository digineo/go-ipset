go-ipset
========

These are bindings to `libipset3`. Currently there is only support for listing sets and adding/removing entries to/from existing sets.
If you need a more feature-rich library then take a look at [janeczku/go-ipset](https://github.com/janeczku/go-ipset).

## Installation

Install dependencies:

On Debian/Ubuntu execute:

    apt install libipset-dev pkg-config

Install go-ipset using the `go get` command:

    go get github.com/digineo/go-ipset

## Usage

Create the ipset before:

    ipset create myset hash:ip timeout 0

Add the import to your program:

```go
import "github.com/digineo/go-ipset"
```

### List all sets

```go
ipset.ListAll()
```

### List a single set

```go
ipset.List("myset")
```

### Add a single entry to the set

```go
ipset.Add("myset", "192.0.2.23")                  // without timeout
ipset.Add("myset", "192.0.2.23", "timeout", "42") // with timeout
```

### Remove a single entry from the set

```go
ipset.Del("myset", "192.0.2.23")
```
