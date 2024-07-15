import ctypes
import struct
import io


def machash(data: bytes, baseHash: int = 0) -> int:
    Hash = (baseHash & 0xFFFFFFFF) ^ 0xAAAAAAAA

    for i in range(0, len(data), 4):
        Hash ^= struct.unpack(">I", data[i : i + 4])[0]

    for i in range(len(data) % 4):
        # xor is not order dependent..
        Hash ^= data[-i]

    print("machash: 0x%08x" % Hash)
    return Hash


class CompressionHeader(ctypes.BigEndianStructure):
    _fields_ = [
        ("magic", ctypes.c_uint32),  # 0x0000
        ("hash", ctypes.c_uint32),  # 0x0004
        ("_0x0008", ctypes.c_uint32),  # 0x0008
        ("_0x000c", ctypes.c_uint32),  # 0x001c
        ("dataOffset", ctypes.c_uint32),  # 0x0010
        ("unkOffset", ctypes.c_uint32),  # 0x0014
    ]

    def checkHash(self, data: bytes) -> bool:
        # todo

        print("Compresshash: 0x%08x" % self.hash)
        return machash(data[8:]) == self.hash

    def valid(self) -> bool:
        return self.magic == 0xA89F000C


def decompress(data, loaderInfo=None):
    Header = CompressionHeader.from_buffer_copy(data)

    if not Header.valid():
        print("Vise invalid header")
        return None

    TableReader = io.BytesIO(data[0x18:])

    # TODO: drop last byte, alignment stuff
    InstrReaderSize = len(data[Header.dataOffset :]) & 0xFFFFFFFFFFFFFFFE
    InstrReader = io.BytesIO(data[Header.dataOffset :])

    # TODO: what is this, is it constant, do i need to scan code segments?
    StaticTable = io.BytesIO()

    if (Header.unkOffset & 0x80000000) != 0:
        StaticTableIdx = Header.unkOffset & 3

        # either 1, 2, 4, 8
        Offset = 1 << StaticTableIdx
        print("TableOffset: 0x%x" % Offset)

        if loaderInfo == None:
            raise Exception("this shit is not implemented. fuck you apple")

        Offset = struct.unpack(">H", loaderInfo[0x6 + Offset :][:2])[0]

        print("Offset: 0x%x" % Offset)

        StaticTable = io.BytesIO(loaderInfo[Offset:])
    else:
        StaticTable = io.BytesIO(data[Header.unkOffset :])

    OutWriter = io.BytesIO()

    try:
        while InstrReader.tell() < InstrReaderSize:
            if False:
                LastPos = OutWriter.tell()
                OutWriter.seek(0, io.SEEK_SET)

                print(OutWriter.read())
                OutWriter.seek(LastPos, io.SEEK_SET)

            b1 = InstrReader.read(1)[0]

            # print("Inst: 0x%02x | 0x%x" % (b1, OutWriter.tell()))
            if (b1 & 1) == 0:
                # print("\t 1")
                # TODO: what is this static table here?
                #

                Offset = (b1 >> 1) * 2

                StaticTable.seek(Offset, io.SEEK_SET)

                OutWriter.write(StaticTable.read(2))

            elif (b1 & 2) == 0:
                # print("\t 2")
                b2 = InstrReader.read(1)[0]

                Length = ((b1 >> 2) & 7) + 1
                Offset = (((b2 << 3) | (b1 >> 5)) + 1) * 2

                # print("0x%02x, 0x%02x" % (b1, b2))
                # print("0x%x, 0x%x" % (Offset, Length))

                # copy **WORDS** 1 by 1 to allow overlap
                for i in range(Length + 1):
                    OutPos = OutWriter.tell()

                    OutWriter.seek(OutPos - Offset, io.SEEK_SET)
                    CopyWord = OutWriter.read(2)

                    OutWriter.seek(OutPos, io.SEEK_SET)
                    OutWriter.write(CopyWord)

            elif (b1 & 4) == 0:
                # print("\t 3")
                b2 = InstrReader.read(1)[0]

                Offset = (((b2 << 5) | (b1 >> 3)) + 0x80) * 2

                if (Offset & 0x2000) != 0:
                    # copy word from table
                    OutWriter.write(TableReader.read(2))

                StaticTable.seek(Offset & 0xDFFF)
                OutWriter.write(StaticTable.read(2))

            elif (b1 & 8) == 0:
                # print("\t 4")
                b2 = InstrReader.read(1)[0]
                b3 = InstrReader.read(1)[0]

                Length = (b1 >> 4) + 1
                Offset = ((b2 << 8) | b3) * 2
                # print("0x%x, 0x%x" % (Offset, Length))

                if Offset > 0xFFFF:
                    # copy word from table
                    OutWriter.write(TableReader.read(2))

                for i in range(Length + 1):
                    OutPos = OutWriter.tell()

                    # fixed offset?
                    OutWriter.seek((Offset & 0xFFFF) + i * 2, io.SEEK_SET)
                    CopyWord = OutWriter.read(2)

                    OutWriter.seek(OutPos)
                    OutWriter.write(CopyWord)
            else:
                # print("\t 5")
                Length = b1 >> 4
                # print("0x%x" % Length)

                for i in range(Length + 1):
                    # copy word from table
                    OutWriter.write(TableReader.read(2))
    except:
        # ghetto way to handle end of data lmao
        pass

    # if theres a trailing byte, copy it
    if (len(data) % 2) == 1:
        OutWriter.write(bytes(data[-1]))

    OutWriter.seek(0, io.SEEK_SET)

    return OutWriter.read()


def scan_vise(code_segs):
    # print(code_segs)
    # for idx, seg in code_segs.items():
    #     print(idx, bytes(seg)[:0x100])
    vise_loaders = [
        bytes(seg) for idx, seg in code_segs.items() if bytes(seg)[0x12:0x16] == b"VISE"
    ]

    # print(vise_loaders)

    if len(vise_loaders) != 1:
        print("Multiple or none vise loaders")
        return None

    # loaderInfo = vise_loaders[0][0x502:]
    loaderInfo = vise_loaders[0][0x4FE:]

    return loaderInfo


def is_compressed(data):
    return len(data) > 4 and struct.unpack(">I", data[:4])[0] == 0xA89F000C


def testBinary(path):
    import macresources
    import collections

    rsrcs = collections.defaultdict(dict)
    for i in macresources.parse_rez_code(open(path, "rb").read()):
        rsrcs[i.type][i.id] = i

    ViseData = scan_vise(rsrcs[b"CODE"])

    print("ViseData: ", ViseData)

    for idx, codeSeg in rsrcs[b"CODE"].items():
        if len(codeSeg) < 0x20:
            continue

        Decompressed = decompress(codeSeg, ViseData)

        if Decompressed == None:
            print("failed decomp")
            continue

        print(Decompressed)
        break


def test(path):
    Data = open(path, "rb").read()

    Header = CompressionHeader.from_buffer_copy(Data)
    print(Header)
    print(Header.valid())
    print(Header.checkHash(Data))


if __name__ == "__main__":
    testBinary(
        "/home/txt/Documents/RE/apple/data/data2/serviceutils/Display Service Utility 4.1.1/Display Service Utility.rdump"
    )
    # test(
    #     "/home/txt/Documents/RE/apple/data/data2/serviceutils/Display Service Utility 4.1.1/dump/0001.CODE"
    # )
