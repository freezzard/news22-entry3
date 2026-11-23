// PNG auditor for the news-image-20261122 entry3 broadsheet.
// Checks, in order: PNG signature, per-chunk CRC32, IDAT inflate +
// Adler-32, and the pinned sha256 of entry.png. Exits 0 only when
// every check passes; prints one verdict line per check otherwise.
// On PASS, copies entry.png to MAKEFUN_OUTPUT_DIR (or /output) as
// entry.png so the grader has an image to score; on FAIL writes
// nothing and exits non-zero.

import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { inflateSync } from "node:zlib";

const PINNED_SHA256 =
  "dc3e79036501863f5f2920baad243065a2a2a0ce16c191a0126d1515c4090a74";
const PINNED_CHUNK_COUNT = 6;
const PNG_SIGNATURE = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
]);

function buildCrcLookup(): Uint32Array {
  const lookup = new Uint32Array(256);
  for (let slot = 0; slot < 256; slot += 1) {
    let running = slot;
    for (let round = 0; round < 8; round += 1) {
      const oddBit = (running & 1) !== 0;
      running = oddBit ? (running >>> 1) ^ 0xedb88320 : running >>> 1;
    }
    lookup[slot] = running >>> 0;
  }
  return lookup;
}

const CRC_LOOKUP = buildCrcLookup();

function crc32Of(octets: Buffer): number {
  let accumulator = 0xffffffff;
  for (const octet of octets) {
    const index = (accumulator ^ octet) & 0xff;
    accumulator = (accumulator >>> 8) ^ CRC_LOOKUP[index];
  }
  return (accumulator ^ 0xffffffff) >>> 0;
}

function adler32Of(octets: Buffer): number {
  const MODULUS = 65521;
  let firstSum = 1;
  let secondSum = 0;
  for (const octet of octets) {
    firstSum = (firstSum + octet) % MODULUS;
    secondSum = (secondSum + firstSum) % MODULUS;
  }
  return ((secondSum << 16) | firstSum) >>> 0;
}

type ChunkNote = {
  label: string;
  payloadBytes: number;
  crcMatches: boolean;
};

type AuditOutcome = {
  signatureMatches: boolean;
  ihdrWidth: number;
  ihdrHeight: number;
  ihdrBitDepth: number;
  ihdrColorType: number;
  ihdrMatches: boolean;
  chunkNotes: ChunkNote[];
  idatInflated: boolean;
  inflatedBytes: number;
  adlerMatches: boolean;
  adlerSeen: number;
  adlerExpected: number;
  shaMatches: boolean;
  shaSeen: string;
};

function auditPng(pngOctets: Buffer): AuditOutcome {
  const outcome: AuditOutcome = {
    signatureMatches: false,
    ihdrWidth: 0,
    ihdrHeight: 0,
    ihdrBitDepth: 0,
    ihdrColorType: 0,
    ihdrMatches: false,
    chunkNotes: [],
    idatInflated: false,
    inflatedBytes: 0,
    adlerMatches: false,
    adlerSeen: 0,
    adlerExpected: 0,
    shaMatches: false,
    shaSeen: "",
  };

  const signatureSlice = pngOctets.subarray(0, PNG_SIGNATURE.length);
  outcome.signatureMatches = signatureSlice.equals(PNG_SIGNATURE);

  const compressedPieces: Buffer[] = [];
  let cursor = PNG_SIGNATURE.length;
  let sawIend = false;

  while (cursor + 12 <= pngOctets.length && sawIend === false) {
    const payloadLength = pngOctets.readUInt32BE(cursor);
    const labelBytes = pngOctets.subarray(cursor + 4, cursor + 8);
    const label = labelBytes.toString("ascii");
    const payloadStart = cursor + 8;
    const payloadEnd = payloadStart + payloadLength;
    const crcStart = payloadEnd;
    const chunkEnd = crcStart + 4;

    const chunkFits = chunkEnd <= pngOctets.length;
    if (chunkFits === false) {
      outcome.chunkNotes.push({
        label,
        payloadBytes: payloadLength,
        crcMatches: false,
      });
      break;
    }

    const crcField = pngOctets.subarray(cursor + 4, crcStart);
    const expectedCrc = pngOctets.readUInt32BE(crcStart);
    const computedCrc = crc32Of(crcField);
    const crcMatches = computedCrc === expectedCrc;
    outcome.chunkNotes.push({
      label,
      payloadBytes: payloadLength,
      crcMatches,
    });

    const isIdat = label === "IDAT";
    if (isIdat) {
      compressedPieces.push(pngOctets.subarray(payloadStart, payloadEnd));
    }

    const isIhdr = label === "IHDR";
    if (isIhdr) {
      const headerPayload = pngOctets.subarray(payloadStart, payloadEnd);
      outcome.ihdrWidth = headerPayload.readUInt32BE(0);
      outcome.ihdrHeight = headerPayload.readUInt32BE(4);
      outcome.ihdrBitDepth = headerPayload[8];
      outcome.ihdrColorType = headerPayload[9];
      outcome.ihdrMatches =
        outcome.ihdrWidth === 1024 &&
        outcome.ihdrHeight === 1024 &&
        outcome.ihdrBitDepth === 8 &&
        outcome.ihdrColorType === 2;
    }

    const isIend = label === "IEND";
    if (isIend) {
      sawIend = true;
    }
    cursor = chunkEnd;
  }

  const zlibBlob = Buffer.concat(compressedPieces);
  const trailerAdler = zlibBlob.readUInt32BE(zlibBlob.length - 4);
  outcome.adlerExpected = trailerAdler;
  const inflated = inflateSync(zlibBlob);
  outcome.idatInflated = true;
  outcome.inflatedBytes = inflated.length;
  outcome.adlerSeen = adler32Of(inflated);
  outcome.adlerMatches = outcome.adlerSeen === outcome.adlerExpected;

  const digest = createHash("sha256").update(pngOctets).digest("hex");
  outcome.shaSeen = digest;
  outcome.shaMatches = digest === PINNED_SHA256;

  return outcome;
}

function verdictLine(passed: boolean): string {
  return passed ? "PASS" : "FAIL";
}

function main(): number {
  const scriptDir = dirname(process.argv[1]);
  const pngOctets = readFileSync(join(scriptDir, "entry.png"));
  const audit = auditPng(pngOctets);

  const crcPassed = audit.chunkNotes.filter(
    (note) => note.crcMatches,
  ).length;
  const crcTotal = audit.chunkNotes.length;
  const allCrcOk = crcTotal > 0 && crcPassed === crcTotal;
  const chunkCountOk = crcTotal === PINNED_CHUNK_COUNT;

  console.log("PNG AUDIT — entry.png");
  console.log(`file bytes: ${pngOctets.length}`);
  console.log(`signature: ${verdictLine(audit.signatureMatches)}`);
  console.log(
    `IHDR: ${audit.ihdrWidth}x${audit.ihdrHeight} bitDepth ${audit.ihdrBitDepth} colorType ${audit.ihdrColorType} — ${verdictLine(audit.ihdrMatches)}`,
  );
  console.log(
    `chunks: ${crcTotal} (expected ${PINNED_CHUNK_COUNT}) — ${verdictLine(chunkCountOk)}`,
  );
  console.log(`chunk CRC: ${crcPassed}/${crcTotal} ok — ${verdictLine(allCrcOk)}`);
  for (const note of audit.chunkNotes) {
    console.log(
      `  ${note.label} ${note.payloadBytes} bytes CRC ${verdictLine(note.crcMatches)}`,
    );
  }
  console.log(
    `inflate: ${verdictLine(audit.idatInflated)} (${audit.inflatedBytes} raw bytes)`,
  );
  console.log(
    `adler32: computed ${audit.adlerSeen}, zlib trailer ${audit.adlerExpected} — ${verdictLine(audit.adlerMatches)}`,
  );
  console.log(`sha256: ${audit.shaSeen}`);
  console.log(`sha256 match: ${verdictLine(audit.shaMatches)}`);

  const everythingOk =
    audit.signatureMatches &&
    audit.ihdrMatches &&
    chunkCountOk &&
    allCrcOk &&
    audit.idatInflated &&
    audit.adlerMatches &&
    audit.shaMatches;
  console.log(`RESULT: ${verdictLine(everythingOk)}`);
  if (everythingOk) {
    const outputDir = process.env.MAKEFUN_OUTPUT_DIR || "/output";
    mkdirSync(outputDir, { recursive: true });
    copyFileSync(join(scriptDir, "entry.png"), join(outputDir, "entry.png"));
    console.log(`wrote ${join(outputDir, "entry.png")}`);
  }
  return everythingOk ? 0 : 1;
}

try {
  process.exitCode = main();
} catch (caughtErr) {
  console.error(`audit crashed: ${(caughtErr as Error).message}`);
  process.exitCode = 1;
}
