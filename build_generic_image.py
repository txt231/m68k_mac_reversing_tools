import sys
import struct
import io
import macresources

import vise

if __name__ == "__main__":
    File = list(macresources.parse_rez_code(open(sys.argv[1], "rb").read()))

    ViseData = vise.scan_vise(
        dict([(res.id, res.data) for res in File if res.type == b"CODE"])
    )

    OutData = io.BytesIO()

    OutData.write(bytes([0] * 0x10000))

    for res in File:
        segData = res.data

        if vise.is_compressed(segData):
            segData = vise.decompress(segData, ViseData)

        while (OutData.tell() % 0x100) != 0:
            OutData.write(bytes([0]))

        OutData.write(segData)

    OutData.seek(0, io.SEEK_SET)
    open(sys.argv[2], "wb").write(OutData.read())
