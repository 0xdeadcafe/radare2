# r2-config Tools

Scripts for generating radare2 zignatures. See the top-level `README.md` for
per-script descriptions and usage examples.

## Environment

All tools use `R2_DATA_DIR` (default: `~/.local/share/radare2`):
- Downloads cached in `$R2_DATA_DIR/cache/`
- Zsigs written to `$R2_DATA_DIR/zigns/`

## Dependencies

- Python 3.8+, r2pipe (`pip install r2pipe`), radare2
- `ar`, `nm` — binutils (Linux .deb extraction)
- `llvm-ar` — Windows SDK .lib extraction (`apt install llvm`)
- `zstd` — OpenWrt toolchain streaming (`apt install zstd`)
- `cabextract` or `7z` — VC++ redistributable extraction

## Notes on generate-winsdk-zsig.py

This tool processes Windows SDK static libraries (`libucrt.lib`, etc.) and
requires a local Windows SDK installation, which is not freely downloadable
automatically. Because of this, no `winsdk-*` zsig files are committed to the
repo — run this tool locally if you have the SDK installed.

```bash
# If you have Windows SDK at a known path:
python3 tool/generate-winsdk-zsig.py --arch x64
# Output goes to zigns/windows/x64/winsdk-*.zsig (not committed upstream)
```
