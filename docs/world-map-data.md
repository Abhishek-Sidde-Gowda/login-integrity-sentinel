# SSH detection map: real country outlines

The `/ssh-detection` attacker-origin map (`web/static/world_land_path.txt`)
is a single SVG path built from real country boundary data - not a
hand-drawn approximation.

## Source

[Natural Earth](https://www.naturalearthdata.com/) 1:110m Admin-0
Countries, fetched from the official vector data mirror maintained by
Natural Earth's own tileset developer:

```
https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson
```

**License: public domain.** Natural Earth's terms of use state no
permission or attribution is required for any use.

## Why this file exists instead of embedding an existing map SVG

The first attempt used a public-domain Wikimedia Commons equirectangular
world map SVG. It looked correct at a glance, but calibrating known
city coordinates (London, Tokyo, Cape Town, ...) against it via the
browser turned up a real, systematic misalignment - the file had
undocumented internal padding/reprojection quirks that put London's
marker over Germany. A map that *looks* real but silently misplaces
every marker is worse than an honestly abstract one.

The fix: generate the landmass path ourselves, in the exact same
coordinate space the dashboard already uses to plot attacker/target
markers (`project(lat, lon)` in `web/templates/ssh_detection.html`).
Since both the map and the markers come from one shared linear
equirectangular formula, they cannot disagree with each other -
verified by overlaying the same 5 test cities and confirming each one
now lands exactly on the correct country.

## Regenerating it

```bash
curl -sL https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson -o /tmp/ne110m.geojson
python3 scripts/build_world_land_path.py /tmp/ne110m.geojson
```

See `scripts/build_world_land_path.py` for the exact projection and
simplification logic (interior holes dropped, points within 2.5 of
the previous kept point thinned - lossless at the panel's rendered
size, cuts the path from ~126KB to ~68KB).
