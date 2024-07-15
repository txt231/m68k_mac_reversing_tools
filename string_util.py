import sys
import struct
import io
import macresources

import vise


def read_string(buf):
    len = buf.read(1)[0]

    return buf.read(len)


def get_string(data, index):
    Reader = io.BytesIO(data)

    for i in range(index - 1):
        print(i, read_string(Reader))

    return read_string(Reader)


if __name__ == "__main__":
    File = list(macresources.parse_rez_code(open(sys.argv[1], "rb").read()))
    Id = int(sys.argv[2])
    StrIdx = int(sys.argv[3])

    ViseData = vise.scan_vise(
        dict([(res.id, res.data) for res in File if res.type == b"CODE"])
    )

    print(
        "\n".join(
            ["(%s, %i)" % (res.type, res.id) for res in File if res.type == b"STR#"]
        )
    )
    Targets = [res for res in File if res.type == b"STR#" and res.id == Id]

    if len(Targets) < 1:
        print("no str found :O")
        exit(1)

    segData = Targets[0].data

    if vise.is_compressed(segData):
        segData = vise.decompress(segData, ViseData)

    StringCount = struct.unpack(">H", segData[:2])
    print("StringCount: %i" % StringCount)

    print("Result: ", get_string(segData[2:], StrIdx))
