#!/usr/bin/env python3
"""Regenerates web/static/world_land_path.txt - a single SVG path
listing every country's exterior ring from Natural Earth's 1:110m
admin-0 countries dataset (public domain, no attribution required:
https://www.naturalearthdata.com/about/terms-of-use/), reprojected
with the EXACT SAME linear equirectangular formula the dashboard uses
for plotting attacker/target markers (see project() in
ssh_detection.html). Generating both from one formula is what
guarantees the landmass and the markers agree with each other -
overlaying a real map image on top of independently-placed markers
was the earlier (broken) approach.

Source data fetched from the official Natural Earth vector mirror:
https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson

Interior rings (holes - e.g. Lesotho inside South Africa) are dropped;
at dashboard scale this is imperceptible and not worth the complexity
of an even-odd fill rule. Points closer than MIN_DIST (in the 1000x500
viewBox's own units) to the previous kept point are thinned - lossless
at the panel's actual rendered size, and it cuts the path from ~126KB
to ~68KB.

Usage:
    curl -sL <source URL above> -o /tmp/ne110m.geojson
    python3 scripts/build_world_land_path.py /tmp/ne110m.geojson
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

W, H = 1000.0, 500.0
MIN_DIST = 2.5
OUTPUT = Path(__file__).resolve().parent.parent / "web" / "static" / "world_land_path.txt"


def project(lon: float, lat: float) -> tuple[float, float]:
    x = (lon + 180.0) / 360.0 * W
    y = (90.0 - lat) / 180.0 * H
    return x, y


def thin(points: list[tuple[float, float]], min_dist: float) -> list[tuple[float, float]]:
    if not points:
        return points
    out = [points[0]]
    for p in points[1:]:
        lx, ly = out[-1]
        if math.hypot(p[0] - lx, p[1] - ly) >= min_dist:
            out.append(p)
    return out


def ring_to_path(ring: list[list[float]]) -> str | None:
    pts = thin([project(lon, lat) for lon, lat in ring], MIN_DIST)
    if len(pts) < 4:
        return None
    return "M" + "L".join(f"{round(x, 1)},{round(y, 1)}" for x, y in pts) + "Z"


def main(geojson_path: str) -> None:
    data = json.load(open(geojson_path))
    parts = []
    for feature in data["features"]:
        geom = feature["geometry"]
        if geom["type"] == "Polygon":
            polys = [geom["coordinates"]]
        elif geom["type"] == "MultiPolygon":
            polys = geom["coordinates"]
        else:
            continue
        for poly in polys:
            s = ring_to_path(poly[0])
            if s:
                parts.append(s)

    full_path = "".join(parts)
    OUTPUT.write_text(full_path)
    print(f"{len(parts)} rings, {len(full_path)} chars -> {OUTPUT}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
