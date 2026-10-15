#!/usr/bin/env python3
"""Build a universal ad-hoc-signed helper and a credential-free portable bundle."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
SKILL=ROOT/'skills/shadowrocket-ai-routing'
DIST=ROOT/'dist'
VERSION='2.0.0'


def main():
    DIST.mkdir(exist_ok=True)
    subprocess.run(['/bin/zsh',str(SKILL/'assets/node-sync/build.sh'),str(DIST)],check=True)
    app=DIST/'Shadowrocket Routing Node Sync.app'
    subprocess.run(['/usr/bin/codesign','--verify','--strict',str(app)],check=True)
    architectures=subprocess.check_output(['/usr/bin/lipo','-archs',str(app/'Contents/MacOS/NodeSync')],text=True).split()
    if set(architectures)!={'x86_64','arm64'}:
        raise RuntimeError('Packaged helper is not universal')
    name='shadowrocket-routing-skill-'+VERSION
    archive=DIST/(name+'.zip')
    with tempfile.TemporaryDirectory(dir=DIST) as tmp:
        stage=Path(tmp)/name
        stage.mkdir()
        shutil.copy2(ROOT/'README.md',stage/'README.md')
        shutil.copytree(SKILL,stage/'skills/shadowrocket-ai-routing',ignore=shutil.ignore_patterns('__pycache__','*.pyc','.DS_Store'))
        shutil.copytree(app,stage/'apps'/app.name)
        files={str(p.relative_to(stage)):hashlib.sha256(p.read_bytes()).hexdigest()
               for p in stage.rglob('*') if p.is_file()}
        (stage/'MANIFEST.json').write_text(json.dumps(dict(version=VERSION,architectures=architectures,
             signature='ad-hoc, not notarized',files=files),indent=2)+'\n')
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
            for p in sorted(stage.rglob('*')):
                if p.is_file():z.write(p,str(p.relative_to(Path(tmp))))
        # Extraction preserves executable mode (Python zip extract does not).
        extracted=Path(tmp)/'extracted'
        subprocess.run(['/usr/bin/ditto','-x','-k',str(archive),str(extracted)],check=True)
        shipped=extracted/name/'apps'/app.name
        subprocess.run(['/usr/bin/codesign','--verify','--strict',str(shipped)],check=True)
        subprocess.run([str(shipped/'Contents/MacOS/NodeSync'),'--self-test'],check=True)
        for relative,digest in files.items():
            if hashlib.sha256((extracted/name/relative).read_bytes()).hexdigest()!=digest:
                raise RuntimeError('Extracted package checksum mismatch')
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    (DIST/'SHA256SUMS.txt').write_text(digest+'  '+archive.name+'\n')
    print(archive)
    print('SHA256 '+digest)


if __name__=='__main__':main()
