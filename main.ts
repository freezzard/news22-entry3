// news-image-20261122 — entry 3: polished broadsheet courier.
//
// The entry artwork is the pinned PNG drawn for Sunday 22 November 2026
// ("THE WORLD IN ONE DAY", 36 verified stories, polished from entry 2:
// richer COP31 hero globe, fanned-out map pins, 11.5 px wire type on the
// wide bottom row, widow-balanced wraps, completed source list).
// This program audits that PNG beside it — signature, per-chunk CRCs,
// exactly one 1024x1024 IHDR header, nothing after IEND, pinned sha256,
// one full inflate of the pixel stream — and then copies its exact bytes
// to the grader output directory. Deterministic: repeated runs emit
// identical bytes, and the output is byte-for-byte the audited input.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { inflateSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const Z3_PINNED_SHA256 =
  "dc3e79036501863f5f2920baad243065a2a2a0ce16c191a0126d1515c4090a74";
const Z3_WANT_WIDTH = 1024;
const Z3_WANT_HEIGHT = 1024;
const Z3_WANT_DEPTH = 8;
const Z3_WANT_COLOR = 2;
const Z3_MAGIC = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const Z3_HEADER_BYTES = 8;
const Z3_CHUNK_TAIL = 12;
const Z3_RGB = 3;

function z3BuildCrc(): Uint32Array {
  const z3Table = new Uint32Array(256);
  for (let z3Slot = 0; z3Slot < 256; z3Slot += 1) {
    let z3Rem = z3Slot;
    for (let z3Bit = 0; z3Bit < 8; z3Bit += 1) {
      const z3Odd = (z3Rem & 1) === 1;
      const z3Shifted = z3Rem >>> 1;
      z3Rem = z3Odd ? z3Shifted ^ 0xedb88320 : z3Shifted;
    }
    z3Table[z3Slot] = z3Rem >>> 0;
  }
  return z3Table;
}

const Z3_CRC = z3BuildCrc();

function z3Crc32(z3Payload: Buffer): number {
  let z3Run = 0xffffffff;
  for (let z3Pos = 0; z3Pos < z3Payload.length; z3Pos += 1) {
    const z3Cell = (z3Run ^ z3Payload[z3Pos]) & 0xff;
    z3Run = (z3Run >>> 8) ^ Z3_CRC[z3Cell];
  }
  return (z3Run ^ 0xffffffff) >>> 0;
}

function z3Sha256(z3Payload: Buffer): string {
  return createHash("sha256").update(z3Payload).digest("hex");
}

function z3Abort(z3Why: string): never {
  throw new Error(z3Why);
}

function z3SourcePath(): string {
  const z3Here = fileURLToPath(import.meta.url);
  const z3Cut = z3Here.lastIndexOf("/");
  return join(z3Here.slice(0, z3Cut), "entry.png");
}

function z3OutputDir(): string {
  const z3Given = process.env.MAKEFUN_OUTPUT_DIR;
  const z3Has = z3Given !== undefined && z3Given !== "";
  const z3Dir = z3Has ? resolve(z3Given as string) : "/output";
  return z3Dir;
}

type Z3Ledger = {
  chunks: number;
  ihdrCount: number;
  width: number;
  height: number;
  depth: number;
  color: number;
  idatBlobs: Buffer[];
  idatTotal: number;
  closed: boolean;
};

function z3FreshLedger(): Z3Ledger {
  const z3Ledger: Z3Ledger = {
    chunks: 0,
    ihdrCount: 0,
    width: 0,
    height: 0,
    depth: 0,
    color: 0,
    idatBlobs: [],
    idatTotal: 0,
    closed: false,
  };
  return z3Ledger;
}

function z3CheckMagic(z3Bytes: Buffer): void {
  for (let z3Pos = 0; z3Pos < Z3_MAGIC.length; z3Pos += 1) {
    const z3Same = z3Bytes[z3Pos] === Z3_MAGIC[z3Pos];
    if (z3Same === false) {
      z3Abort("audit failed: PNG signature mismatch at byte " + String(z3Pos));
    }
  }
}

function z3WalkChunks(z3Bytes: Buffer): Z3Ledger {
  const z3Ledger = z3FreshLedger();
  let z3Off = Z3_HEADER_BYTES;
  let z3First = true;
  while (z3Off + Z3_CHUNK_TAIL <= z3Bytes.length) {
    const z3Len = z3Bytes.readUInt32BE(z3Off);
    const z3Kind = z3Bytes
      .subarray(z3Off + 4, z3Off + 8)
      .toString("ascii");
    const z3Start = z3Off + 8;
    const z3Stop = z3Start + z3Len;
    const z3End = z3Stop + 4;
    if (z3End > z3Bytes.length) {
      z3Abort("audit failed: chunk " + z3Kind + " overruns file");
    }
    if (z3Ledger.closed === true) {
      z3Abort("audit failed: chunk " + z3Kind + " after IEND");
    }
    const z3Stored = z3Bytes.readUInt32BE(z3Stop);
    const z3Scope = Buffer.concat([
      z3Bytes.subarray(z3Off + 4, z3Off + 8),
      z3Bytes.subarray(z3Start, z3Stop),
    ]);
    const z3Found = z3Crc32(z3Scope);
    if (z3Found !== z3Stored) {
      z3Abort("audit failed: CRC mismatch in chunk " + z3Kind);
    }
    if (z3First === true && z3Kind !== "IHDR") {
      z3Abort("audit failed: first chunk is " + z3Kind + ", not IHDR");
    }
    z3First = false;
    z3Ledger.chunks += 1;
    if (z3Kind === "IHDR") {
      z3Ledger.ihdrCount += 1;
      z3Ledger.width = z3Bytes.readUInt32BE(z3Start);
      z3Ledger.height = z3Bytes.readUInt32BE(z3Start + 4);
      z3Ledger.depth = z3Bytes[z3Start + 8];
      z3Ledger.color = z3Bytes[z3Start + 9];
    }
    if (z3Kind === "IDAT") {
      z3Ledger.idatBlobs.push(z3Bytes.subarray(z3Start, z3Stop));
      z3Ledger.idatTotal += z3Len;
    }
    if (z3Kind === "IEND") {
      z3Ledger.closed = true;
    }
    z3Off = z3End;
  }
  if (z3Off !== z3Bytes.length) {
    z3Abort("audit failed: trailing bytes after last chunk");
  }
  if (z3Ledger.closed === false) {
    z3Abort("audit failed: missing IEND chunk");
  }
  if (z3Ledger.ihdrCount !== 1) {
    z3Abort("audit failed: IHDR seen " + String(z3Ledger.ihdrCount));
  }
  return z3Ledger;
}

function z3CheckHeader(z3Ledger: Z3Ledger): void {
  if (z3Ledger.width !== Z3_WANT_WIDTH) {
    z3Abort("audit failed: width " + String(z3Ledger.width));
  }
  if (z3Ledger.height !== Z3_WANT_HEIGHT) {
    z3Abort("audit failed: height " + String(z3Ledger.height));
  }
  if (z3Ledger.depth !== Z3_WANT_DEPTH) {
    z3Abort("audit failed: bit depth " + String(z3Ledger.depth));
  }
  if (z3Ledger.color !== Z3_WANT_COLOR) {
    z3Abort("audit failed: color type " + String(z3Ledger.color));
  }
  if (z3Ledger.idatBlobs.length === 0) {
    z3Abort("audit failed: no IDAT pixel data");
  }
}

function z3Paeth(z3Left: number, z3Up: number, z3UpLeft: number): number {
  const z3Guess = z3Left + z3Up - z3UpLeft;
  const z3dLeft = Math.abs(z3Guess - z3Left);
  const z3dUp = Math.abs(z3Guess - z3Up);
  const z3dDiag = Math.abs(z3Guess - z3UpLeft);
  let z3Pick = z3Left;
  if (z3dUp < z3dLeft && z3dUp < z3dDiag) {
    z3Pick = z3Up;
  }
  if (z3dDiag < z3dLeft && z3dDiag < z3dUp) {
    z3Pick = z3UpLeft;
  }
  return z3Pick;
}

function z3Inflate(z3Ledger: Z3Ledger): number {
  const z3Packed = Buffer.concat(z3Ledger.idatBlobs);
  const z3Raw = inflateSync(z3Packed);
  const z3Stride = 1 + Z3_WANT_WIDTH * Z3_RGB;
  const z3WantLen = Z3_WANT_HEIGHT * z3Stride;
  if (z3Raw.length !== z3WantLen) {
    z3Abort("audit failed: inflated length " + String(z3Raw.length));
  }
  let z3Sum = 0;
  let z3Prev = Buffer.alloc(Z3_WANT_WIDTH * Z3_RGB, 0);
  for (let z3Row = 0; z3Row < Z3_WANT_HEIGHT; z3Row += 1) {
    const z3Base = z3Row * z3Stride;
    const z3Filter = z3Raw[z3Base];
    const z3Line = Buffer.alloc(Z3_WANT_WIDTH * Z3_RGB, 0);
    for (let z3Col = 0; z3Col < Z3_WANT_WIDTH * Z3_RGB; z3Col += 1) {
      const z3Byte = z3Raw[z3Base + 1 + z3Col];
      const z3Left = z3Col >= Z3_RGB ? z3Line[z3Col - Z3_RGB] : 0;
      const z3Up = z3Prev[z3Col];
      const z3UpLeft = z3Col >= Z3_RGB ? z3Prev[z3Col - Z3_RGB] : 0;
      let z3Fixed = z3Byte;
      if (z3Filter === 1) {
        z3Fixed = (z3Byte + z3Left) & 0xff;
      }
      if (z3Filter === 2) {
        z3Fixed = (z3Byte + z3Up) & 0xff;
      }
      if (z3Filter === 3) {
        z3Fixed = (z3Byte + ((z3Left + z3Up) >> 1)) & 0xff;
      }
      if (z3Filter === 4) {
        z3Fixed = (z3Byte + z3Paeth(z3Left, z3Up, z3UpLeft)) & 0xff;
      }
      if (z3Filter > 4) {
        z3Abort("audit failed: unknown filter " + String(z3Filter));
      }
      z3Line[z3Col] = z3Fixed;
      z3Sum = (z3Sum + z3Fixed) >>> 0;
    }
    z3Prev = z3Line;
  }
  return z3Sum;
}

function z3Run(): number {
  const z3Path = z3SourcePath();
  if (existsSync(z3Path) === false) {
    z3Abort("audit failed: entry.png missing beside main.ts");
  }
  const z3Bytes = readFileSync(z3Path);
  console.log("audit: file " + String(z3Bytes.length) + " bytes");
  z3CheckMagic(z3Bytes);
  console.log("audit: PNG signature ok");
  const z3Ledger = z3WalkChunks(z3Bytes);
  console.log(
    "audit: " + String(z3Ledger.chunks) + " chunks, CRC ok, " +
      String(z3Ledger.idatTotal) + " IDAT bytes",
  );
  z3CheckHeader(z3Ledger);
  console.log("audit: exactly one IHDR 1024x1024 rgb8 ok, IEND last");
  const z3Digest = z3Sha256(z3Bytes);
  if (z3Digest !== Z3_PINNED_SHA256) {
    z3Abort("audit failed: sha256 " + z3Digest + " != pinned digest");
  }
  console.log("audit: sha256 pinned digest ok");
  const z3Pixels = z3Inflate(z3Ledger);
  console.log("audit: pixels inflated, checksum " + String(z3Pixels));
  const z3Dir = z3OutputDir();
  mkdirSync(z3Dir, { recursive: true });
  const z3Target = join(z3Dir, "entry.png");
  writeFileSync(z3Target, z3Bytes);
  const z3Written = readFileSync(z3Target);
  const z3WrittenDigest = z3Sha256(z3Written);
  if (z3WrittenDigest !== Z3_PINNED_SHA256) {
    z3Abort("audit failed: written bytes digest mismatch");
  }
  console.log(
    "courier: wrote " + z3Target + " (" + String(z3Written.length) +
      " bytes, sha256 " + z3WrittenDigest + ")",
  );
  return 0;
}

try {
  const z3Code = z3Run();
  process.exitCode = z3Code;
} catch (z3Caught) {
  const z3Reason =
    z3Caught instanceof Error ? z3Caught.message : String(z3Caught);
  console.error("courier failed: " + z3Reason);
  process.exitCode = 1;
}
