#!/usr/bin/env python3
"""Render the original HotTurkey vector artwork to SVG, PNG and macOS ICNS."""
import json
import platform
import shutil
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent


def build_icons():
    build=ROOT/'build';build.mkdir(exist_ok=True)
    source=ROOT/'assets/icon.json';icon=json.loads(source.read_text())
    background=icon['background'];x,y,w,h=background['rect'];a,b=background['colors']
    elements=[f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024"><defs><linearGradient id="tile" x2="1" y2="1"><stop stop-color="{a}"/><stop offset="1" stop-color="{b}"/></linearGradient></defs>',
              f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{background["radius"]}" fill="url(#tile)"/>']
    for shape in icon['shapes']:
        fill=shape['fill']
        if 'circle' in shape:
            cx,cy,r=shape['circle'];elements.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{fill}"/>')
        else:
            path=' '.join(' '.join(map(str,command)) for command in shape['path'])
            elements.append(f'<path d="{path}" fill="{fill}"/>')
    svg='\n'.join(elements+['</svg>'])+'\n'
    for target in ['assets/icon.svg','web/icon.svg','extension/icon.svg']:(ROOT/target).write_text(svg)
    cache=build/'swift-cache';cache.mkdir(exist_ok=True)
    renderer=build/'HotTurkeyIconRenderer'
    architecture='arm64' if platform.machine() in {'arm64','aarch64'} else 'x86_64'
    subprocess.run(['/usr/bin/swiftc','-swift-version','5','-target',architecture+'-apple-macos12.0','-O','-module-cache-path',str(cache),str(ROOT/'native/IconRenderer.swift'),'-framework','AppKit','-framework','ImageIO','-o',str(renderer)],check=True)
    images=build/'icon-images';subprocess.run([str(renderer),str(source),str(images)],check=True)
    iconset=build/'HotTurkey.iconset';iconset.mkdir(exist_ok=True)
    for logical in [16,32,128,256,512]:
        for scale in [1,2]:
            filename=f'icon_{logical}x{logical}'+('@2x' if scale==2 else '')+'.png'
            shutil.copy2(images/f'icon-{logical*scale}.png',iconset/filename)
    destination=build/'HotTurkey.icns'
    subprocess.run(['/usr/bin/iconutil','-c','icns',str(iconset),'-o',str(destination)],check=True)
    extension=ROOT/'extension/icons';extension.mkdir(exist_ok=True)
    for size in [16,19,32,38,48,128]:shutil.copy2(images/f'icon-{size}.png',extension/f'icon-{size}.png')
    return destination


if __name__=='__main__':print(build_icons())
