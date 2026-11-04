"""Build altwarden/web/static/world.json from world-atlas (ISC) country shapes (Natural Earth, public domain).

Run once when updating the map: python scripts/build_world_map.py
"""
import json
import pathlib
import urllib.request

SOURCE = "https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json"
TARGET = pathlib.Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static" / "world.json"


def main() -> None:
    topology = json.load(urllib.request.urlopen(SOURCE, timeout=60))
    scale, translate = topology["transform"]["scale"], topology["transform"]["translate"]
    arcs = []
    for arc in topology["arcs"]:
        x = y = 0
        points = []
        for dx, dy in arc:
            x += dx
            y += dy
            points.append((round(x * scale[0] + translate[0], 2), round(y * scale[1] + translate[1], 2)))
        arcs.append(points)

    def ring(indices):
        points = []
        for index in indices:
            segment = arcs[index] if index >= 0 else list(reversed(arcs[~index]))
            points.extend(segment[1:] if points else segment)
        return points

    shapes = {}
    for geometry in topology["objects"]["countries"]["geometries"]:
        code = geometry.get("id")
        if code is None:
            continue
        polygons = geometry["arcs"] if geometry["type"] == "MultiPolygon" else [geometry["arcs"]]
        shapes.setdefault(code, []).extend(ring(polygon[0]) for polygon in polygons)
    TARGET.write_text(json.dumps(shapes, separators=(",", ":")), encoding="utf-8")
    print(len(shapes), "countries,", TARGET.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
