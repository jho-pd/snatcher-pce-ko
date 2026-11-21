package main

import (
	"bufio"
	"crypto/md5"
	_ "embed"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

//go:embed patch.xdelta
var patchData []byte

//go:embed out.cue
var outCue []byte

const version = "1.0.2"

var in = bufio.NewReader(os.Stdin)

func pauseExit(code int) {
	fmt.Println()
	fmt.Print("Enter 키를 누르면 창이 닫힙니다.")
	in.ReadString('\n')
	os.Exit(code)
}

func fail(format string, a ...interface{}) {
	fmt.Println()
	fmt.Println("[실패] " + fmt.Sprintf(format, a...))
	pauseExit(1)
}

func isOurs(name string) bool {
	return strings.HasPrefix(strings.ToLower(filepath.Base(name)), "snatcher_ko")
}

// candidates in a directory, best first
func scanDir(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var cue, ccd, raw []string
	for _, e := range ents {
		if e.IsDir() || isOurs(e.Name()) || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".cue":
			cue = append(cue, p)
		case ".ccd":
			ccd = append(ccd, p)
		case ".iso", ".bin", ".img":
			if st, err := e.Info(); err == nil && st.Size() == canonSize {
				raw = append(raw, p)
			}
		}
	}
	sort.Strings(cue)
	sort.Strings(ccd)
	sort.Strings(raw)
	return append(append(cue, ccd...), raw...)
}

func openAny(p string) (*Disc, error) {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".cue":
		return openCue(p)
	case ".ccd":
		return openCCD(p)
	case ".img":
		// CloneCD image: prefer its .ccd
		base := strings.TrimSuffix(p, filepath.Ext(p))
		for _, x := range []string{".ccd", ".CCD"} {
			if _, err := os.Stat(base + x); err == nil {
				return openCCD(base + x)
			}
		}
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("폴더가 아니라 파일을 선택해 주세요")
	}
	// a .bin/.iso: use a cue with the same name if present
	base := strings.TrimSuffix(p, filepath.Ext(p))
	for _, x := range []string{".cue", ".CUE"} {
		if _, err := os.Stat(base + x); err == nil {
			return openCue(base + x)
		}
	}
	if st.Size() == canonSize {
		return openRaw(p)
	}
	return nil, fmt.Errorf("cue 또는 ccd 파일을 선택해 주세요 (트랙 정보가 필요합니다)")
}

type bar struct {
	label string
	total int64
	last  int
}

func (b *bar) set(n int64) {
	pct := int(n * 100 / b.total)
	if pct != b.last {
		b.last = pct
		fmt.Printf("\r  %s %3d%%", b.label, pct)
		if pct >= 100 {
			fmt.Println()
		}
	}
}

type hashFile struct {
	f *os.File
	h hash.Hash
	n int64
}

func (w *hashFile) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	w.h.Write(p[:n])
	w.n += int64(n)
	return n, err
}
func (w *hashFile) ReadAt(p []byte, off int64) (int, error) { return w.f.ReadAt(p, off) }

func main() {
	consoleSetup()
	fmt.Println("========================================")
	fmt.Println(" 스내처 (Snatcher) PC엔진 CD-ROM²")
	fmt.Println(" 한글패치 v" + version)
	fmt.Println(" 제작: 마이콜 & 은유 아빠")
	fmt.Println("========================================")
	fmt.Println()

	var src string
	if len(os.Args) > 1 {
		src = strings.Join(os.Args[1:], " ")
	} else {
		exe, _ := os.Executable()
		dirs := []string{filepath.Dir(exe)}
		if wd, err := os.Getwd(); err == nil && wd != dirs[0] {
			dirs = append(dirs, wd)
		}
		var cands []string
		seen := map[string]bool{}
		for _, d := range dirs {
			for _, c := range scanDir(d) {
				k := c
				if a, err := filepath.Abs(c); err == nil {
					k = a
				}
				if r, err := filepath.EvalSymlinks(k); err == nil {
					k = r
				}
				k = strings.ToLower(k)
				dup := seen[k]
				if st, err := os.Stat(c); err == nil {
					for _, o := range cands {
						if so, err := os.Stat(o); err == nil && os.SameFile(st, so) {
							dup = true
						}
					}
				}
				if !dup {
					seen[k] = true
					cands = append(cands, c)
				}
			}
		}
		switch {
		case len(cands) == 1:
			src = cands[0]
		case len(cands) > 1:
			fmt.Println("이 폴더에서 원본 이미지 후보를 찾았습니다:")
			for i, c := range cands {
				fmt.Printf("  %d) %s\n", i+1, filepath.Base(c))
			}
			fmt.Print("번호를 입력하세요: ")
			s, _ := in.ReadString('\n')
			k, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || k < 1 || k > len(cands) {
				fail("번호가 올바르지 않습니다.")
			}
			src = cands[k-1]
		default:
			fmt.Println("일본판 스내처 원본 이미지의 cue 또는 ccd 파일을")
			fmt.Println("이 창으로 끌어다 놓고 Enter를 누르세요.")
			fmt.Println("(또는 이 프로그램을 원본 이미지와 같은 폴더에 두고 다시 실행하세요.)")
			fmt.Print("> ")
			s, _ := in.ReadString('\n')
			src = s
		}
	}
	src = strings.TrimSpace(src)
	src = strings.Trim(src, "\"'")
	src = strings.ReplaceAll(src, "\\ ", " ")
	if src == "" {
		fail("파일이 지정되지 않았습니다.")
	}
	fmt.Println("원본: " + src)

	d, err := openAny(src)
	if err != nil {
		fail("%v", err)
	}
	defer d.Close()
	if len(d.tracks) != 24 || !d.tracks[1].data || !d.tracks[23].data {
		fail("스내처 일본판(PC엔진 CD) 이미지가 아닌 것 같습니다. (트랙 %d개)", len(d.tracks))
	}
	fmt.Printf("형식: %s, 트랙 24개\n", d.desc)

	off, ok := findOffset(d)
	if !ok {
		fmt.Println("주의: 오디오 위치를 찾지 못해 보정 없이 진행합니다.")
	} else if off != 0 {
		fmt.Printf("오디오 밀림 %d샘플을 보정합니다.\n", off/4)
	}
	c := &Canon{d: d, off: off}

	fmt.Println()
	fmt.Println("[1/3] 원본 확인 중...")
	for _, t := range []int{1, 23} {
		b := &bar{label: fmt.Sprintf("데이터 트랙 %d", t+1), total: canonLen[t] * S, last: -1}
		m, err := md5Range(c, canonPos[t]*S, canonLen[t]*S, b.set)
		if err != nil {
			fail("읽기 오류: %v", err)
		}
		if m != dataMD5[t] {
			fail("게임 데이터가 기준 원본과 다릅니다.\n       일본판 'Snatcher CD-ROMantic' 원본 이미지가 맞는지 확인해 주세요.")
		}
	}
	b := &bar{label: "전체 이미지", total: canonSize, last: -1}
	full, err := md5Range(c, 0, canonSize, b.set)
	if err != nil {
		fail("읽기 오류: %v", err)
	}
	strict := full == canonMD5
	if strict {
		fmt.Println("  기준 원본과 완전히 일치합니다.")
	} else {
		fmt.Println("  게임 데이터는 일치하지만 오디오가 기준과 조금 다릅니다.")
		fmt.Println("  그대로 패치합니다. (게임은 정상, 결과 파일 해시만 달라집니다)")
	}

	outDir := filepath.Join(filepath.Dir(src), "Snatcher_KO")
	if o := os.Getenv("SNKO_OUT"); o != "" {
		outDir = o
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fail("폴더를 만들 수 없습니다: %v", err)
	}
	outIso := filepath.Join(outDir, "Snatcher_KO.iso")
	f, err := os.Create(outIso)
	if err != nil {
		fail("파일을 만들 수 없습니다: %v", err)
	}
	w := &hashFile{f: f, h: md5.New()}
	fmt.Println()
	fmt.Println("[2/3] 한글패치 적용 중...")
	b2 := &bar{label: "패치", total: 633991008, last: -1}
	bad, err := ApplyVCDIFF(patchData, c, w, strict, b2.set)
	f.Close()
	if err != nil {
		os.Remove(outIso)
		fail("패치 중 오류: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "Snatcher_KO.cue"), outCue, 0644); err != nil {
		fail("cue 파일을 쓸 수 없습니다: %v", err)
	}
	fmt.Println()
	fmt.Println("[3/3] 결과 확인")
	got := hex.EncodeToString(w.h.Sum(nil))
	if strict {
		if got != targetMD5 {
			fail("결과 파일 해시가 다릅니다 (%s). 다시 시도해 주세요.", got)
		}
		fmt.Println("  결과 MD5 " + got + " (정상)")
	} else {
		fmt.Printf("  결과 MD5 %s (오디오 차이 %d구간, 게임 데이터 정상)\n", got, bad)
	}
	_ = io.EOF
	fmt.Println()
	fmt.Println("완료!")
	fmt.Println("  " + outDir)
	fmt.Println("  폴더의 Snatcher_KO.cue 를 에뮬레이터에서 여세요.")
	fmt.Println("  (SUPER CD-ROM² System 3.0 바이오스가 필요합니다)")
	pauseExit(0)
}
