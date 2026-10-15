#!/bin/zsh
set -euo pipefail
task_root=${0:A:h}
output_dir=${1:-$task_root/../../../../dist}
mkdir -p "$output_dir"
output_dir=${output_dir:A}
build_dir=$(/usr/bin/mktemp -d "$output_dir/.nodesync-build.XXXXXX")
trap '/bin/rm -rf "$build_dir"' EXIT
staged_app="$build_dir/Shadowrocket Routing Node Sync.app"
mkdir -p "$staged_app/Contents/MacOS"
sdk=$(/usr/bin/xcrun --sdk macosx --show-sdk-path)
# One signed universal app supports Intel and Apple Silicon, macOS 13+.
for arch in arm64 x86_64; do
  /usr/bin/xcrun swiftc -O -file-prefix-map "$task_root"=/source -debug-prefix-map "$task_root"=/source -sdk "$sdk" -target "${arch}-apple-macosx13.0" -framework AppKit "$task_root/NodeSync.swift" -o "$build_dir/NodeSync-$arch"
done
/usr/bin/lipo -create "$build_dir/NodeSync-arm64" "$build_dir/NodeSync-x86_64" -output "$staged_app/Contents/MacOS/NodeSync"
/usr/bin/python3 -I - "$staged_app" <<'PY'
from pathlib import Path
import plistlib,sys
(Path(sys.argv[1])/'Contents/Info.plist').write_bytes(plistlib.dumps(dict(
 CFBundleIdentifier='org.shadowrocket-routing.NodeSync',CFBundleName='Shadowrocket 节点同步（迁移版）',
 CFBundleDisplayName='Shadowrocket 节点同步（迁移版）',CFBundleExecutable='NodeSync',
 CFBundlePackageType='APPL',CFBundleVersion='200',CFBundleShortVersionString='2.0.0',
 LSMinimumSystemVersion='13.0',NSHighResolutionCapable=True)))
PY
/usr/bin/codesign --force --sign - --entitlements "$task_root/entitlements.plist" "$staged_app"
/usr/bin/codesign --verify --strict "$staged_app"
"$staged_app/Contents/MacOS/NodeSync" --self-test
"$staged_app/Contents/MacOS/NodeSync" --window-self-test --background
app_path="$output_dir/Shadowrocket Routing Node Sync.app"
if [[ -e "$app_path" ]]; then /bin/mv "$app_path" "$build_dir/previous.app"; fi
if ! /bin/mv "$staged_app" "$app_path"; then
  if [[ -e "$build_dir/previous.app" ]]; then /bin/mv "$build_dir/previous.app" "$app_path"; fi
  exit 1
fi
print "Built: $app_path"
