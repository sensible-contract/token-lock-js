import { BN } from "@sensible-contract/bsv";
import { toHex } from "@sensible-contract/sdk-core/lib/scryptlib";
import { Proto } from "@sensible-contract/sdk-core";

export const PROTO_VERSION = 1;

const NFT_ID_LEN = 20;
const SATOSHIS_PRICE_LEN = 8;
const OWNER_ADDRESS_LEN = 20;
const TOKEN_INDEX_LEN = 8;
const GENESIS_LEN = 20;
const CODEHASH_LEN = 20;

const NFT_ID_OFFSET = NFT_ID_LEN + Proto.getHeaderLen();
const SATOSHIS_PRICE_OFFSET = SATOSHIS_PRICE_LEN + NFT_ID_OFFSET;
const OWNER_ADDRESS_OFFSET = OWNER_ADDRESS_LEN + SATOSHIS_PRICE_OFFSET;
const TOKEN_INDEX_OFFSET = TOKEN_INDEX_LEN + OWNER_ADDRESS_OFFSET;
const GENESIS_OFFSET = GENESIS_LEN + TOKEN_INDEX_OFFSET;
const CODEHASH_OFFSET = CODEHASH_LEN + GENESIS_OFFSET;

export function getNftID(script: Buffer) {
  return toHex(
    script.slice(
      script.length - NFT_ID_OFFSET,
      script.length - NFT_ID_OFFSET + NFT_ID_LEN
    )
  );
}

export function getSatoshisPrice(script: Buffer): BN {
  if (script.length < SATOSHIS_PRICE_OFFSET) return BN.Zero;
  return BN.fromBuffer(
    script.slice(
      script.length - SATOSHIS_PRICE_OFFSET,
      script.length - SATOSHIS_PRICE_OFFSET + SATOSHIS_PRICE_LEN
    ),
    { endian: "little" }
  );
}

export function getOwnerAddress(script: Buffer) {
  if (script.length < OWNER_ADDRESS_OFFSET) return "";
  return script
    .slice(
      script.length - OWNER_ADDRESS_OFFSET,
      script.length - OWNER_ADDRESS_OFFSET + OWNER_ADDRESS_LEN
    )
    .toString("hex");
}

export function getTokenIndex(script: Buffer): BN {
  if (script.length < TOKEN_INDEX_OFFSET) return BN.Zero;
  return BN.fromBuffer(
    script.slice(
      script.length - TOKEN_INDEX_OFFSET,
      script.length - TOKEN_INDEX_OFFSET + TOKEN_INDEX_LEN
    ),
    { endian: "little" }
  );
}

export function getGenesis(script: Buffer) {
  if (script.length < GENESIS_OFFSET) return "";
  return script
    .slice(
      script.length - GENESIS_OFFSET,
      script.length - GENESIS_OFFSET + GENESIS_LEN
    )
    .toString("hex");
}

export function getCodeHash(script: Buffer) {
  if (script.length < CODEHASH_OFFSET) return "";
  return script
    .slice(
      script.length - CODEHASH_OFFSET,
      script.length - CODEHASH_OFFSET + CODEHASH_LEN
    )
    .toString("hex");
}

export type FormatedDataPart = {
  codehash: string;
  genesis: string;
  ownerAddress: string;
  protoVersion?: number;
  protoType?: Proto.PROTO_TYPE;
};

export function newDataPart({
  codehash,
  genesis,
  ownerAddress,
  protoVersion,
  protoType,
}: FormatedDataPart): Buffer {
  const codehashBuf = Buffer.alloc(20, 0);
  if (codehash) {
    codehashBuf.write(codehash, "hex");
  }

  const genesisBuf = Buffer.alloc(20, 0);
  if (genesis) {
    genesisBuf.write(genesis, "hex");
  }

  const ownerAddressBuf = Buffer.alloc(OWNER_ADDRESS_OFFSET, 0);
  if (ownerAddress) {
    ownerAddressBuf.write(ownerAddress, "hex");
  }

  const protoVersionBuf = Buffer.alloc(Proto.PROTO_VERSION_LEN);
  if (protoVersion) {
    protoVersionBuf.writeUInt32LE(protoVersion);
  }

  const protoTypeBuf = Buffer.alloc(Proto.PROTO_TYPE_LEN, 0);
  if (protoType) {
    protoTypeBuf.writeUInt32LE(protoType);
  }
  return Buffer.concat([
    codehashBuf,
    genesisBuf,
    ownerAddressBuf,
    protoVersionBuf,
    protoTypeBuf,
    Proto.PROTO_FLAG,
  ]);
}

export function parseDataPart(scriptBuf: Buffer): FormatedDataPart {
  let codehash = getCodeHash(scriptBuf);
  let genesis = getGenesis(scriptBuf);
  let ownerAddress = getOwnerAddress(scriptBuf);
  let protoVersion = Proto.getProtoVersioin(scriptBuf);
  let protoType = Proto.getProtoType(scriptBuf);
  return {
    codehash,
    genesis,
    ownerAddress,
    protoVersion,
    protoType,
  };
}
