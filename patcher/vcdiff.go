package main

// Minimal VCDIFF (RFC 3284) decoder with the xdelta3 extensions used by
// "xdelta3 -e" (adler32 window checksum, LZMA secondary compression).

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/adler32"
	"io"

	"github.com/ulikunitz/xz"
)

const (
	vcdSource  = 0x01
	vcdTarget  = 0x02
	vcdAdler32 = 0x04
)

type inst struct {
	typ  byte // 0 noop, 1 add, 2 run, 3 copy
	size byte
	mode byte
}

var codeTable [256][2]inst

func init() {
	i := 0
	codeTable[i][0] = inst{2, 0, 0}
	i++
	for s := 0; s <= 17; s++ {
		codeTable[i][0] = inst{1, byte(s), 0}
		i++
	}
	for m := 0; m <= 8; m++ {
		codeTable[i][0] = inst{3, 0, byte(m)}
		i++
		for s := 4; s <= 18; s++ {
			codeTable[i][0] = inst{3, byte(s), byte(m)}
			i++
		}
	}
	for m := 0; m <= 5; m++ {
		for a := 1; a <= 4; a++ {
			for c := 4; c <= 6; c++ {
				codeTable[i][0] = inst{1, byte(a), 0}
				codeTable[i][1] = inst{3, byte(c), byte(m)}
				i++
			}
		}
	}
	for m := 6; m <= 8; m++ {
		for a := 1; a <= 4; a++ {
			codeTable[i][0] = inst{1, byte(a), 0}
			codeTable[i][1] = inst{3, 4, byte(m)}
			i++
		}
	}
	for m := 0; m <= 8; m++ {
		codeTable[i][0] = inst{3, 4, byte(m)}
		codeTable[i][1] = inst{1, 1, 0}
		i++
	}
	if i != 256 {
		panic("code table")
	}
}

func readVarint(r io.ByteReader) (uint64, error) {
	var v uint64
	for n := 0; n < 10; n++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v = v<<7 | uint64(b&0x7f)
		if b&0x80 == 0 {
			return v, nil
		}
	}
	return 0, errors.New("varint too long")
}

func varintBuf(b []byte, p *int) (uint64, error) {
	var v uint64
	for n := 0; n < 10; n++ {
		if *p >= len(b) {
			return 0, errors.New("truncated varint")
		}
		c := b[*p]
		*p++
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			return v, nil
		}
	}
	return 0, errors.New("varint too long")
}

// secondaryStreams collects the LZMA-compressed sections of every window.
// xdelta3 keeps one LZMA stream per section type (data, inst, addr) running
// across windows, so each type is decoded as one continuous xz stream.
func secondaryStreams(d []byte) ([3][]byte, error) {
	var res [3][]byte
	p := 4
	if len(d) < 6 {
		return res, errors.New("patch too short")
	}
	hdr := d[p]
	p++
	if hdr&0x01 != 0 {
		if d[p] != 2 {
			return res, fmt.Errorf("unsupported secondary compressor %d", d[p])
		}
		p++
	}
	if hdr&0x04 != 0 {
		n, err := varintBuf(d, &p)
		if err != nil {
			return res, err
		}
		p += int(n)
	}
	var comp [3][]byte
	var total [3]uint64
	for p < len(d) {
		w := d[p]
		p++
		if w&(vcdSource|vcdTarget) != 0 {
			varintBuf(d, &p)
			varintBuf(d, &p)
		}
		varintBuf(d, &p)
		varintBuf(d, &p)
		if p >= len(d) {
			return res, errors.New("truncated window")
		}
		di := d[p]
		p++
		var l [3]uint64
		var err error
		for k := 0; k < 3; k++ {
			if l[k], err = varintBuf(d, &p); err != nil {
				return res, err
			}
		}
		if w&vcdAdler32 != 0 {
			p += 4
		}
		for k := 0; k < 3; k++ {
			sec := d[p : p+int(l[k])]
			p += int(l[k])
			if di&(1<<k) != 0 {
				q := 0
				u, err := varintBuf(sec, &q)
				if err != nil {
					return res, err
				}
				total[k] += u
				comp[k] = append(comp[k], sec[q:]...)
			}
		}
	}
	for k := 0; k < 3; k++ {
		if total[k] == 0 {
			continue
		}
		r, err := xz.NewReader(bytes.NewReader(comp[k]))
		if err != nil {
			return res, err
		}
		res[k] = make([]byte, total[k])
		if _, err := io.ReadFull(r, res[k]); err != nil {
			return res, fmt.Errorf("secondary decode: %v", err)
		}
	}
	return res, nil
}

// Output is where the target is written. It must also allow reading back
// (for VCD_TARGET windows).
type Output interface {
	io.Writer
	io.ReaderAt
}

// ApplyVCDIFF decodes patch against src, writing the target to out.
// If strict is false, adler32 mismatches are counted but not fatal.
func ApplyVCDIFF(patch []byte, src io.ReaderAt, out Output, strict bool, progress func(int64)) (badWindows int, err error) {
	streams, err := secondaryStreams(patch)
	if err != nil {
		return 0, err
	}
	pos := [3]int{}
	take := func(k int, sec []byte) ([]byte, error) {
		p := 0
		usize, e := varintBuf(sec, &p)
		if e != nil {
			return nil, e
		}
		if pos[k]+int(usize) > len(streams[k]) {
			return nil, errors.New("secondary stream overflow")
		}
		b := streams[k][pos[k] : pos[k]+int(usize)]
		pos[k] += int(usize)
		return b, nil
	}
	br := bufio.NewReaderSize(bytes.NewReader(patch), 1<<20)
	var magic [4]byte
	if _, err = io.ReadFull(br, magic[:]); err != nil {
		return
	}
	if magic != [4]byte{0xd6, 0xc3, 0xc4, 0x00} {
		return 0, errors.New("not a VCDIFF patch")
	}
	hdr, _ := br.ReadByte()
	if hdr&0x01 != 0 {
		br.ReadByte()
	}
	if hdr&0x02 != 0 {
		return 0, errors.New("custom code tables are not supported")
	}
	if hdr&0x04 != 0 {
		n, e := readVarint(br)
		if e != nil {
			return 0, e
		}
		if _, err = br.Discard(int(n)); err != nil {
			return
		}
	}
	var written int64
	var srcCache *blockCache
	for {
		winInd, e := br.ReadByte()
		if e == io.EOF {
			return badWindows, nil
		}
		if e != nil {
			return badWindows, e
		}
		var segLen, segPos uint64
		if winInd&(vcdSource|vcdTarget) != 0 {
			if segLen, err = readVarint(br); err != nil {
				return
			}
			if segPos, err = readVarint(br); err != nil {
				return
			}
		}
		if _, err = readVarint(br); err != nil { // delta encoding length
			return
		}
		tlen, e2 := readVarint(br)
		if e2 != nil {
			return badWindows, e2
		}
		dind, _ := br.ReadByte()
		ldata, _ := readVarint(br)
		linst, _ := readVarint(br)
		laddr, e3 := readVarint(br)
		if e3 != nil {
			return badWindows, e3
		}
		var cksum uint32
		if winInd&vcdAdler32 != 0 {
			var c [4]byte
			if _, err = io.ReadFull(br, c[:]); err != nil {
				return
			}
			cksum = uint32(c[0])<<24 | uint32(c[1])<<16 | uint32(c[2])<<8 | uint32(c[3])
		}
		data := make([]byte, ldata)
		insts := make([]byte, linst)
		addrs := make([]byte, laddr)
		for _, s := range [][]byte{data, insts, addrs} {
			if _, err = io.ReadFull(br, s); err != nil {
				return
			}
		}
		if dind&0x01 != 0 {
			if data, err = take(0, data); err != nil {
				return
			}
		}
		if dind&0x02 != 0 {
			if insts, err = take(1, insts); err != nil {
				return
			}
		}
		if dind&0x04 != 0 {
			if addrs, err = take(2, addrs); err != nil {
				return
			}
		}
		// source segment (read lazily through a block cache)
		var seg *blockCache
		if winInd&(vcdSource|vcdTarget) != 0 {
			if winInd&vcdTarget != 0 {
				seg = newCache(out, int64(segPos), int64(segLen))
			} else {
				if srcCache == nil {
					srcCache = newCache(src, 0, 1<<62)
				}
				srcCache.base = int64(segPos)
				srcCache.n = int64(segLen)
				seg = srcCache
			}
		}
		segN := uint64(0)
		if seg != nil {
			segN = uint64(seg.n)
		}
		tgt := make([]byte, 0, tlen)
		var near [4]uint64
		nextSlot := 0
		var same [3 * 256]uint64
		dp, ip, ap := 0, 0, 0
		doCopy := func(size uint64, mode byte) error {
			here := segN + uint64(len(tgt))
			var addr uint64
			var e error
			switch {
			case mode == 0:
				addr, e = varintBuf(addrs, &ap)
			case mode == 1:
				var v uint64
				v, e = varintBuf(addrs, &ap)
				addr = here - v
			case mode >= 2 && mode <= 5:
				var v uint64
				v, e = varintBuf(addrs, &ap)
				addr = near[mode-2] + v
			default:
				if ap >= len(addrs) {
					return errors.New("addr overflow")
				}
				addr = same[int(mode-6)*256+int(addrs[ap])]
				ap++
			}
			if e != nil {
				return e
			}
			near[nextSlot] = addr
			nextSlot = (nextSlot + 1) % 4
			same[addr%(3*256)] = addr
			for k := uint64(0); k < size; k++ {
				a := addr + k
				if a < segN {
					c, e := seg.at(int64(a))
					if e != nil {
						return e
					}
					tgt = append(tgt, c)
				} else {
					t := a - segN
					if t >= uint64(len(tgt)) {
						return errors.New("bad copy address")
					}
					tgt = append(tgt, tgt[t])
				}
			}
			return nil
		}
		for ip < len(insts) {
			code := insts[ip]
			ip++
			for h := 0; h < 2; h++ {
				in := codeTable[code][h]
				if in.typ == 0 {
					continue
				}
				size := uint64(in.size)
				if size == 0 {
					if size, err = varintBuf(insts, &ip); err != nil {
						return
					}
				}
				switch in.typ {
				case 1:
					if dp+int(size) > len(data) {
						return badWindows, errors.New("data overflow")
					}
					tgt = append(tgt, data[dp:dp+int(size)]...)
					dp += int(size)
				case 2:
					if dp >= len(data) {
						return badWindows, errors.New("data overflow")
					}
					b := data[dp]
					dp++
					for k := uint64(0); k < size; k++ {
						tgt = append(tgt, b)
					}
				case 3:
					if err = doCopy(size, in.mode); err != nil {
						return
					}
				}
			}
		}
		if uint64(len(tgt)) != tlen {
			return badWindows, fmt.Errorf("window size mismatch %d != %d", len(tgt), tlen)
		}
		if winInd&vcdAdler32 != 0 && adler32.Checksum(tgt) != cksum {
			badWindows++
			if strict {
				return badWindows, errors.New("checksum mismatch: source image differs")
			}
		}
		if _, err = out.Write(tgt); err != nil {
			return
		}
		written += int64(len(tgt))
		if progress != nil {
			progress(written)
		}
	}
}

const blk = 1 << 16

type blockCache struct {
	r       io.ReaderAt
	base, n int64
	blocks  map[int64][]byte
	order   []int64
}

func newCache(r io.ReaderAt, base, n int64) *blockCache {
	return &blockCache{r: r, base: base, n: n, blocks: map[int64][]byte{}}
}

func (c *blockCache) at(a int64) (byte, error) {
	p := c.base + a
	k := p / blk
	b, ok := c.blocks[k]
	if !ok {
		b = make([]byte, blk)
		if _, err := c.r.ReadAt(b, k*blk); err != nil && err != io.EOF {
			return 0, err
		}
		if len(c.order) >= 512 {
			old := c.order[0]
			c.order = c.order[1:]
			delete(c.blocks, old)
		}
		c.blocks[k] = b
		c.order = append(c.order, k)
	}
	return b[p-k*blk], nil
}
