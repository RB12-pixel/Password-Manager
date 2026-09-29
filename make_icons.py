import zlib, struct, os
os.makedirs("static", exist_ok=True)

def png(size, path):
    bg, fg = (59, 130, 246), (255, 255, 255)
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            u, v = x / size, y / size
            c = bg
            if 0.30 <= u <= 0.70 and 0.46 <= v <= 0.74:
                c = fg
            else:
                dx, dy = u - 0.5, v - 0.46
                if dy <= 0 and 0.11 <= (dx*dx + dy*dy) ** 0.5 <= 0.17:
                    c = fg
            row += bytes(c)
        rows.append(bytes(row))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    data = (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(rows), 9))
            + chunk(b"IEND", b""))
    open(path, "wb").write(data)

png(192, "static/icon-192.png")
png(512, "static/icon-512.png")
