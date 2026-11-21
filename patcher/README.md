# Snatcher_KO_Patch (패치 프로그램 소스)

여러 형식의 일본판 이미지(단일 BIN/ISO, 트랙별 bin+cue, CloneCD)를 읽고, 기준 원본과 같은 형태로 되돌린 뒤 릴리스의 xdelta 패치를 적용합니다. 게임 데이터는 들어 있지 않습니다.

- `disc.go`: cue/ccd 읽기, 프리갭 처리, 오디오 오프셋 찾기, 기준 원본 형태로 읽기
- `vcdiff.go`: VCDIFF(xdelta3) 디코더 (LZMA 보조 압축 포함)
- `main.go`: 화면 안내, 해시 확인, 결과 파일 쓰기

빌드: 릴리스 zip의 `snatcher-pce-ko-v1.0.2.xdelta` 를 이 폴더에 `patch.xdelta` 라는 이름으로 넣고

```
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o Snatcher_KO_Patch.exe .
```
