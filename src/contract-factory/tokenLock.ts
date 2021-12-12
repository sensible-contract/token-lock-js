import * as bsv from "@sensible-contract/bsv";
import { BN } from "@sensible-contract/bsv";
import {
  ContractAdapter,
  dummyAddress,
  dummyPadding,
  dummyPk,
  dummyRabinPubKey,
  dummySigBE,
  dummyTxId,
  PLACE_HOLDER_SIG,
  Proto,
} from "@sensible-contract/sdk-core";
import {
  buildContractClass,
  buildTypeClasses,
  Bytes,
  FunctionCall,
  Int,
  PubKey,
  Ripemd160,
  Sig,
  toHex,
} from "@sensible-contract/sdk-core/lib/scryptlib";
import { TxComposer } from "@sensible-contract/tx-composer";
import * as tokenLockProto from "../contract-proto/tokenLock.proto";
const Signature = bsv.crypto.Signature;
export const sighashType = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;
const desc = require("../contract-desc/tokenLock_desc.json");
const { RabinSig } = buildTypeClasses(desc);
export enum NFT_SELL_OP {
  SELL = 1,
  CANCEL = 2,
}
export class TokenLock extends ContractAdapter {
  private _formatedDataPart: tokenLockProto.FormatedDataPart;
  constuctParams: {
    ownerPubKeyHash: Ripemd160;
    witnessPubkey: Int;
    matureTime: Int;
  };

  static getClass() {
    let TokenLockContractClass = buildContractClass(desc);

    return TokenLockContractClass;
  }

  constructor(constuctParams: {
    ownerPubKeyHash: Ripemd160;
    witnessPubkey: Int;
    matureTime: Int;
  }) {
    let TokenLockContractClass = TokenLock.getClass();
    let contract = new TokenLockContractClass(
      constuctParams.ownerPubKeyHash,
      constuctParams.witnessPubkey,
      constuctParams.matureTime
    );
    super(contract);
    this.constuctParams = constuctParams;
  }

  static fromASM(asm: string) {
    let TokenLockContractClass = TokenLock.getClass();
    let contract = TokenLockContractClass.fromASM(asm);
    let params = contract.scriptedConstructor.params;
    let ownerPubKeyHash = params[0];
    let witnessPubkey = params[1];
    let matureTime = params[2];
    return new TokenLock({ ownerPubKeyHash, witnessPubkey, matureTime });
  }

  clone() {
    let contract = new TokenLock(this.constuctParams);
    contract.setFormatedDataPart(this.getFormatedDataPart());
    return contract;
  }

  public setFormatedDataPart(dataPart: tokenLockProto.FormatedDataPart): void {
    this._formatedDataPart = Object.assign(
      {},
      this._formatedDataPart,
      dataPart
    );
    this._formatedDataPart.protoVersion = tokenLockProto.PROTO_VERSION;
    this._formatedDataPart.protoType = Proto.PROTO_TYPE.NFT_SELL;
    super.setDataPart(
      toHex(tokenLockProto.newDataPart(this._formatedDataPart))
    );
  }

  public getFormatedDataPart() {
    return this._formatedDataPart;
  }

  public setFormatedDataPartFromLockingScript(script: bsv.Script) {
    let dataPart = tokenLockProto.parseDataPart(script.toBuffer());
    this.setFormatedDataPart(dataPart);
  }

  public unlock({
    sig,
    ownerPubKey,
    unlockTime,
    rabinSig,
  }: {
    sig: Sig;
    ownerPubKey: PubKey;
    unlockTime: Int;
    rabinSig: {
      s: Int;
      padding: Bytes;
    };
  }) {
    return this._contract.unlock(
      sig,
      ownerPubKey,
      unlockTime,
      new RabinSig(rabinSig)
    ) as FunctionCall;
  }
}

export class TokenLockFactory {
  public static lockingScriptSize: number;

  public static getLockingScriptSize() {
    if (!this.lockingScriptSize)
      this.lockingScriptSize = this.calLockingScriptSize();
    return this.lockingScriptSize;
  }

  public static createContract(
    ownerPubKeyHash: Ripemd160,
    witnessPubkey: Int,
    matureTime: Int
  ): TokenLock {
    return new TokenLock({ ownerPubKeyHash, witnessPubkey, matureTime });
  }

  public static createFromASM(asm: string): TokenLock {
    return TokenLock.fromASM(asm);
  }

  public static getDummyInstance() {
    let contract = this.createContract(
      new Ripemd160(toHex(dummyAddress.hashBuffer)),
      new Int(dummyRabinPubKey.toString(10)),
      new Int(Date.now())
    );
    return contract;
  }

  public static createDummyTx() {
    const dummySatoshis = 100000000000000;
    const dummyUnlockScript =
      "483045022100e922b0bd9c58a4bbc9fce7799238b3bb140961bb061f6a820120bcf61746ec3c022062a926ce4cd34837c4c922bb1f6b8e971450808d078edec9260dc04594e135ea412102ed9e3017533cb75a86d471b94005c87154a2cb27f435480fdffbc5e963c46a8d";
    let lockContract = this.getDummyInstance();
    const txComposer = new TxComposer();

    let utxos: any[] = [];
    for (let i = 0; i < 3; i++) {
      utxos.push({
        txId: dummyTxId,
        outputIndex: 0,
        satoshis: dummySatoshis,
        address: dummyAddress.toString(),
      });
    }
    const p2pkhInputIndexs = utxos.map((utxo) => {
      const inputIndex = txComposer.appendP2PKHInput(utxo);
      txComposer.addInputInfo({
        inputIndex,
        address: utxo.address.toString(),
        sighashType,
      });
      return inputIndex;
    });

    const lockContractOutputIndex = txComposer.appendOutput({
      lockingScript: lockContract.lockingScript,
      satoshis: txComposer.getDustThreshold(
        lockContract.lockingScript.toBuffer().length
      ),
    });

    let changeOutputIndex = txComposer.appendChangeOutput(dummyAddress);

    utxos.forEach((v, index) => {
      txComposer.getInput(index).setScript(new bsv.Script(dummyUnlockScript));
    });

    return txComposer;
  }

  public static calLockingScriptSize() {
    let contract = this.getDummyInstance();
    let size = contract.lockingScript.toBuffer().length;
    return size;
  }

  public static calUnlockingScriptSize() {
    let contract = this.getDummyInstance();
    const sig = Buffer.from(PLACE_HOLDER_SIG, "hex");
    let unlockResult = contract.unlock({
      sig: new Sig(toHex(sig)),
      ownerPubKey: new PubKey(toHex(dummyPk)),
      unlockTime: new Int(Date.now()),
      rabinSig: {
        s: new Int(BN.fromString(dummySigBE, 16).toString(10)),
        padding: new Bytes(dummyPadding),
      },
    });
    return (unlockResult.toScript() as bsv.Script).toBuffer().length;
  }
}
