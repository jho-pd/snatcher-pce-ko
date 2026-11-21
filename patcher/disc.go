package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const S = 2352

// canonical (patch base) layout: file position and length of each track, in sectors
var canonPos = []int64{0, 3949, 38069, 42940, 54152, 65935, 78513, 88465, 93515, 96018, 127683, 148961, 158445, 164216, 170770, 171874, 183641, 193595, 194927, 209250, 211478, 211778, 212079, 234549}
var canonLen = []int64{3949, 34120, 4871, 11212, 11783, 12578, 9952, 5050, 2503, 31665, 21278, 9484, 5771, 6554, 1104, 11767, 9954, 1332, 14323, 2228, 300, 301, 22470, 33973}

const canonSize = int64(268522) * S
const canonMD5 = "959c78130d97d4308c6586e06d0fa056"
const targetMD5 = "37e05be13c1f47c85ef36b7022ee57b9"

var dataMD5 = map[int]string{1: "ccb76e86b1ec7f69fb4b75280ac49d53", 23: "a9fe6f22961ef2d99a92b4f105353f42"}

// fingerprints: 64 bytes at canonical track t, sector 300
type fprint struct {
	track int
	hex   string
}

var fprints = []fprint{
	{2, "fd01af011502cd011002c601bc0181010801dd003100ffff94ff52ff91ff31ff14009effab004b00ef00b400d100b8007b0078003c003e0056004f00aa009400"},
	{9, "82fca1ffb8fcc1ffd7fcf4ffd6fc2600edfc3d00f2fc6d002ffdbb00acfdf1002dfeef006efe0e0191fe5c01a0fea9018efecb016efed60151fe18024bfe7302"},
	{18, "b1fc2ff95afc36f931fc35fa3dfc59fb35fc1dfb38fc74f919fc2ef897fbe8f703fbabf83ffa46f993f95ff881f9d2f6bef9c0f563fad1f5ccfad7f686fa23f8"},
}

type extent struct {
	lba  int64 // absolute start sector
	n    int64 // sectors
	f    *os.File
	foff int64 // byte offset in file
}

type track struct {
	lba  int64 // absolute LBA of INDEX 01
	data bool
}

// Disc is a user's image seen as one linear stream of absolute sectors.
type Disc struct {
	ext    []extent
	tracks []track
	files  []*os.File
	desc   string
}

func (d *Disc) Close() {
	for _, f := range d.files {
		f.Close()
	}
}

// ReadAt reads bytes at absolute byte position pos (may be negative); unstored areas read as zero.
func (d *Disc) readAbs(p []byte, pos int64) error {
	for i := range p {
		p[i] = 0
	}
	end := pos + int64(len(p))
	for _, e := range d.ext {
		es := e.lba * S
		ee := es + e.n*S
		lo, hi := max64(es, pos), min64(ee, end)
		if lo >= hi {
			continue
		}
		if _, err := e.f.ReadAt(p[lo-pos:hi-pos], e.foff+(lo-es)); err != nil && err != io.EOF {
			return err
		}
	}
	return nil
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func msf(s string) (int64, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 3 {
		return 0, fmt.Errorf("bad time %q", s)
	}
	var v [3]int64
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0, err
		}
		v[i] = int64(n)
	}
	return (v[0]*60+v[1])*75 + v[2], nil
}

func openCue(path string) (*Disc, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	d := &Disc{desc: "CUE"}
	type ftrack struct {
		idx01  int64
		pregap int64
		data   bool
		hasIdx bool
	}
	type cfile struct {
		f      *os.File
		size   int64
		tracks []*ftrack
	}
	var files []*cfile
	var cur *ftrack
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff"))
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "FILE "):
			name := line[5:]
			if i := strings.Index(name, "\""); i >= 0 {
				if j := strings.LastIndex(name, "\""); j > i {
					name = name[i+1 : j]
				}
			} else if k := strings.LastIndex(name, " "); k > 0 {
				name = name[:k]
			}
			fp := filepath.Join(dir, filepath.FromSlash(strings.ReplaceAll(name, "\\", "/")))
			f, err := os.Open(fp)
			if err != nil {
				// try case-insensitive / same base name
				f, err = os.Open(filepath.Join(dir, filepath.Base(fp)))
				if err != nil {
					d.Close()
					return nil, fmt.Errorf("cue에 적힌 파일을 찾을 수 없습니다: %s", name)
				}
			}
			d.files = append(d.files, f)
			st, _ := f.Stat()
			files = append(files, &cfile{f: f, size: st.Size()})
		case strings.HasPrefix(up, "TRACK "):
			if len(files) == 0 {
				return nil, errors.New("cue 형식 오류 (FILE 없음)")
			}
			cur = &ftrack{data: !strings.Contains(up, "AUDIO")}
			files[len(files)-1].tracks = append(files[len(files)-1].tracks, cur)
		case strings.HasPrefix(up, "PREGAP ") && cur != nil:
			v, err := msf(line[7:])
			if err != nil {
				return nil, err
			}
			cur.pregap = v
		case strings.HasPrefix(up, "INDEX 01 ") && cur != nil:
			v, err := msf(line[9:])
			if err != nil {
				return nil, err
			}
			cur.idx01 = v
			cur.hasIdx = true
		}
	}
	var p int64
	for _, cf := range files {
		nsec := cf.size / S
		last := int64(0)
		for _, t := range cf.tracks {
			if t.pregap > 0 {
				if t.idx01 > last {
					d.ext = append(d.ext, extent{p, t.idx01 - last, cf.f, last * S})
					p += t.idx01 - last
					last = t.idx01
				}
				p += t.pregap
			}
			d.tracks = append(d.tracks, track{p + (t.idx01 - last), t.data})
		}
		if nsec > last {
			d.ext = append(d.ext, extent{p, nsec - last, cf.f, last * S})
			p += nsec - last
		}
	}
	if len(d.tracks) == 0 {
		return nil, errors.New("cue에 트랙이 없습니다")
	}
	d.normalize()
	return d, nil
}

func (d *Disc) normalize() {
	sh := d.tracks[0].lba
	if sh == 0 {
		return
	}
	for i := range d.ext {
		d.ext[i].lba -= sh
	}
	for i := range d.tracks {
		d.tracks[i].lba -= sh
	}
}

func openCCD(path string) (*Disc, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(path, filepath.Ext(path))
	var f *os.File
	for _, ext := range []string{".img", ".IMG", ".Img"} {
		if f, err = os.Open(base + ext); err == nil {
			break
		}
	}
	if f == nil {
		return nil, errors.New("ccd와 같은 이름의 .img 파일을 찾을 수 없습니다")
	}
	st, _ := f.Stat()
	d := &Disc{desc: "CloneCD", files: []*os.File{f}}
	d.ext = []extent{{0, st.Size() / S, f, 0}}
	type ent struct {
		point   int
		plba    int64
		control int
	}
	var ents []ent
	var e *ent
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[Entry") {
			ents = append(ents, ent{point: -1})
			e = &ents[len(ents)-1]
			continue
		}
		if strings.HasPrefix(line, "[") {
			e = nil
			continue
		}
		if e == nil {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 0, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(kv[0]) {
		case "Point":
			e.point = int(v)
		case "PLBA":
			e.plba = v
		case "Control":
			e.control = int(v)
		}
	}
	for t := 1; t <= 99; t++ {
		found := false
		for _, x := range ents {
			if x.point == t {
				d.tracks = append(d.tracks, track{x.plba, x.control&4 != 0})
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	if len(d.tracks) == 0 {
		f.Close()
		return nil, errors.New("ccd에서 트랙 정보를 읽지 못했습니다")
	}
	d.normalize()
	return d, nil
}

// openRaw treats a single file without a cue as the canonical layout.
func openRaw(path string) (*Disc, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, _ := f.Stat()
	d := &Disc{desc: "단일 이미지", files: []*os.File{f}}
	// rebuild canonical absolute layout: pregaps of 225 before track 2, 150 before 3, 225 before 24
	var gaps = map[int]int64{1: 225, 2: 150, 23: 225}
	var p int64
	var last int64
	for t := 0; t < 24; t++ {
		if g, ok := gaps[t]; ok {
			d.ext = append(d.ext, extent{p, canonPos[t] - last, f, last * S})
			p += canonPos[t] - last
			last = canonPos[t]
			p += g
		}
		d.tracks = append(d.tracks, track{p + canonPos[t] - last, t == 1 || t == 23})
	}
	d.ext = append(d.ext, extent{p, st.Size()/S - last, f, last * S})
	return d, nil
}

// Canon presents the user's disc as the canonical patch-base image.
type Canon struct {
	d   *Disc
	off int64 // audio byte offset
}

func (c *Canon) ReadAt(p []byte, pos int64) (int, error) {
	n := 0
	for n < len(p) {
		cur := pos + int64(n)
		if cur >= canonSize {
			return n, io.EOF
		}
		// find track
		t := 23
		for i := 0; i < 24; i++ {
			if cur < (canonPos[i]+canonLen[i])*S {
				t = i
				break
			}
		}
		tEnd := (canonPos[t] + canonLen[t]) * S
		chunk := min64(int64(len(p)-n), tEnd-cur)
		o := int64(0)
		if !c.d.tracks[t].data {
			o = c.off
		}
		src := c.d.tracks[t].lba*S + (cur - canonPos[t]*S) + o
		if err := c.d.readAbs(p[n:n+int(chunk)], src); err != nil {
			return n, err
		}
		n += int(chunk)
	}
	return n, nil
}

// findOffset locates the audio offset (bytes) by searching fingerprints.
func findOffset(d *Disc) (int64, bool) {
	const win = 48000 * 4 // +-48000 samples
	for _, fp := range fprints {
		want, _ := hex.DecodeString(fp.hex)
		center := d.tracks[fp.track].lba*S + 300*S
		buf := make([]byte, 2*win+len(want))
		if err := d.readAbs(buf, center-win); err != nil {
			continue
		}
		if i := bytes.Index(buf, want); i >= 0 {
			return int64(i) - win, true
		}
	}
	return 0, false
}

func md5Range(r io.ReaderAt, start, n int64, progress func(int64)) (string, error) {
	h := md5.New()
	buf := make([]byte, 4<<20)
	for done := int64(0); done < n; {
		k := min64(int64(len(buf)), n-done)
		if _, err := r.ReadAt(buf[:k], start+done); err != nil && err != io.EOF {
			return "", err
		}
		h.Write(buf[:k])
		done += k
		if progress != nil {
			progress(done)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
