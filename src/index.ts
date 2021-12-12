import * as bsv from "@sensible-contract/bsv";
import { BN } from "@sensible-contract/bsv";
import {
  getRabinDatas,
  PLACE_HOLDER_PUBKEY,
  PLACE_HOLDER_SIG,
  Prevouts,
  SizeTransaction,
  Utils,
} from "@sensible-contract/sdk-core";
import {
  Bytes,
  Int,
  PubKey,
  Ripemd160,
  Sig,
  SigHashPreimage,
  toHex,
} from "@sensible-contract/sdk-core/lib/scryptlib";
import {
  TokenInput,
  TokenOutput,
  TokenSigner,
} from "@sensible-contract/token-js";
import { TokenFactory } from "@sensible-contract/token-js/lib/contract-factory/token";
import {
  TokenUnlockContractCheck,
  TokenUnlockContractCheckFactory,
  TOKEN_UNLOCK_TYPE,
} from "@sensible-contract/token-js/lib/contract-factory/tokenUnlockContractCheck";
import * as ftProto from "@sensible-contract/token-js/lib/contract-proto/token.proto";
import { TxComposer } from "@sensible-contract/tx-composer";
import { WitnessOnChainApi } from "@sensible-contract/witnessonchain-api";
import { TokenLock, TokenLockFactory } from "./contract-factory/tokenLock";
const Signature = bsv.crypto.Signature;
export const sighashType = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;

const _ = bsv.deps._;
type ParamUtxo = {
  txId: string;
  outputIndex: number;
  satoshis: number;
  address: string;
};

const defaultOracleConfig = {
  apiPrefix: "https://woc.satoplay.com",
  pubKey:
    "5564ec0d4b0b39747b12be662ac368764a38a84319b3acbd320e29ac2f1bd786fd9980d9f3980e91793b6b9b4dbd43281da5c7c0f505dd50dd2015ab186469f4a91a57ae5b91a96d3c8467ca2d49f80a6ad26d6f8ad799c3e10bcfe7e43b4ffb5e5e958ccb68684d0a09c9a48df3050ae5be5189fc6f2c46a9137981a9184f39cb40188cf1753089af8d2eb7ba89fd2a253ae16072126dbc037db1009e1575e7b1c72666d397be3e2c57d997485345cc6e5e25a5b5c0ee92f25e885a743b26cae47620209a035d05ff215c355954ded8e8c4bc4d6c4e09e0997e7395040092da552f92b3aa2998a15598a83f3c1a4e1310b1d67b8e7998b7ff450ce81cb9a05672827443331fb1a7cfa0e344ff21d4b9311f0e6169fd8b5cc57bb3fda8ed671345699b0775d7f62e251ef60f22daaaa3b464af8c90cdf898c01ec4644f4003b6176897f10f2b64a6e4fe9602eb3277a3c303b3cc38a98afa1c9dd4c7eb77b8ed1f5ec40150a5cbc5d9f3575bad88adc1db1b6a3b789e53a4a9db5eaa17018c2c",
};

type OracleConfig = {
  apiPrefix: string;
  pubKey: string;
};
export class WitnessOracle {
  api: WitnessOnChainApi;
  rabinPubKey: BN;
  rabinPubKeyHash: Buffer;

  constructor(oracleConfig: OracleConfig = defaultOracleConfig) {
    this.api = new WitnessOnChainApi(oracleConfig.apiPrefix);
    this.rabinPubKey = BN.fromBuffer(Buffer.from(oracleConfig.pubKey, "hex"), {
      endian: "little",
    });
    this.rabinPubKeyHash = bsv.crypto.Hash.sha256ripemd160(
      Buffer.from(oracleConfig.pubKey, "hex")
    );
  }
}

export async function getLockTokenAddress({
  witnessOracle,
  ownerAddress,
  matureTime,
}: {
  witnessOracle: WitnessOracle;
  ownerAddress: string;
  matureTime: number;
}): Promise<string> {
  let address = new bsv.Address(ownerAddress);

  let tokenLockContract = TokenLockFactory.createContract(
    new Ripemd160(toHex(address.hashBuffer)),
    new Int(witnessOracle.rabinPubKey.toString(10)),
    new Int(matureTime)
  );
  return new bsv.Address(
    Utils.getScriptHashBuf(tokenLockContract.lockingScript.toBuffer())
  ).toString();
}

export async function createTokenLockContractTx({
  witnessOracle,
  ownerAddress,
  matureTime,
  utxos,
  changeAddress,
}: {
  witnessOracle: WitnessOracle;
  ownerAddress: string;
  matureTime: number;
  utxos: ParamUtxo[];
  changeAddress?: string;
}) {
  if (!changeAddress) {
    changeAddress = utxos[0].address;
  }

  let address = new bsv.Address(ownerAddress);
  let tokenLockContract = TokenLockFactory.createContract(
    new Ripemd160(toHex(address.hashBuffer)),
    new Int(witnessOracle.rabinPubKey.toString(10)),
    new Int(matureTime)
  );

  let txComposer = new TxComposer();
  //tx addInput utxo
  const unlockCheck_p2pkhInputIndexs = utxos.map((utxo) => {
    const inputIndex = txComposer.appendP2PKHInput(utxo);
    txComposer.addInputInfo({
      inputIndex,
      address: utxo.address.toString(),
      sighashType,
    });
    return inputIndex;
  });

  const unlockCheckOutputIndex = txComposer.appendOutput({
    lockingScript: tokenLockContract.lockingScript,
    satoshis: txComposer.getDustThreshold(
      tokenLockContract.lockingScript.toBuffer().length
    ),
  });

  let changeOutputIndex = txComposer.appendChangeOutput(changeAddress);

  return { txComposer, tokenLockContract };
}

createTokenLockContractTx.estimateFee = function ({
  utxoMaxCount = 10,
}: {
  utxoMaxCount?: number;
}) {
  let p2pkhInputNum = utxoMaxCount;
  let stx = new SizeTransaction();
  for (let i = 0; i < p2pkhInputNum; i++) {
    stx.addP2PKHInput();
  }

  stx.addOutput(TokenLockFactory.getLockingScriptSize());
  stx.addP2PKHOutput();
  return stx.getFee();
};

export async function createUnlockTx({
  witnessOracle,
  tokenSigner,
  tokenInputs,
  tokenOutputs,

  tokenLockContract,
  tokenLockTxComposer,

  unlockCheckContract,
  unlockCheckTxComposer,

  utxos,
  changeAddress,
  opreturnData,
}: {
  witnessOracle: WitnessOracle;
  tokenSigner: TokenSigner;

  tokenInputs?: TokenInput[];
  tokenOutputs: TokenOutput[];
  tokenLockContract: TokenLock;
  tokenLockTxComposer: TxComposer;

  unlockCheckContract: TokenUnlockContractCheck;
  unlockCheckTxComposer: TxComposer;

  utxos?: ParamUtxo[];
  changeAddress?: string;
  opreturnData?: any;
}): Promise<{
  txComposer: TxComposer;
}> {
  if (!changeAddress) {
    changeAddress = utxos[0].address;
  }

  let tokenLockUtxo = {
    txId: tokenLockTxComposer.getTxId(),
    outputIndex: 0,
    satoshis: tokenLockTxComposer.getOutput(0).satoshis,
    lockingScript: tokenLockTxComposer.getOutput(0).script,
  };

  let unlockCheckUtxo = {
    txId: unlockCheckTxComposer.getTxId(),
    outputIndex: 0,
    satoshis: unlockCheckTxComposer.getOutput(0).satoshis,
    lockingScript: unlockCheckTxComposer.getOutput(0).script,
  };

  let {
    rabinDatas,
    checkRabinDatas,
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
  } = await getRabinDatas(
    tokenSigner.signers,
    tokenSigner.signerSelecteds,
    tokenInputs.map((v) => v.satotxInfo)
  );

  let oracleData = await witnessOracle.api.getTimestamp();

  const txComposer = new TxComposer();
  let prevouts = new Prevouts();

  const tokenLockInputIndex = txComposer.appendInput(tokenLockUtxo);
  prevouts.addVout(tokenLockUtxo.txId, tokenLockUtxo.outputIndex);
  txComposer.addInputInfo({
    inputIndex: tokenLockInputIndex,
    address: tokenOutputs[0].address,
    sighashType,
  });

  let inputTokenScript: bsv.Script;
  let inputTokenAmountArray = Buffer.alloc(0);
  let inputTokenAddressArray = Buffer.alloc(0);

  const tokenInputIndexs = tokenInputs.map((ftUtxo) => {
    const inputIndex = txComposer.appendInput(ftUtxo);
    prevouts.addVout(ftUtxo.txId, ftUtxo.outputIndex);
    inputTokenScript = ftUtxo.lockingScript;
    inputTokenAddressArray = Buffer.concat([
      inputTokenAddressArray,
      ftUtxo.tokenAddress.hashBuffer,
    ]);

    inputTokenAmountArray = Buffer.concat([
      inputTokenAmountArray,
      ftUtxo.tokenAmount.toBuffer({
        endian: "little",
        size: 8,
      }),
    ]);
    return inputIndex;
  });

  //tx addInput utxo
  const p2pkhInputIndexs = utxos.map((utxo) => {
    const inputIndex = txComposer.appendP2PKHInput(utxo);
    prevouts.addVout(utxo.txId, utxo.outputIndex);
    txComposer.addInputInfo({
      inputIndex,
      address: utxo.address.toString(),
      sighashType,
    });
    return inputIndex;
  });

  //添加routeCheck为最后一个输入
  const checkInputIndex = txComposer.appendInput(unlockCheckUtxo);
  prevouts.addVout(unlockCheckUtxo.txId, unlockCheckUtxo.outputIndex);

  let recervierArray = Buffer.alloc(0);
  let receiverTokenAmountArray = Buffer.alloc(0);
  let tokenOutputSatoshiArray = Buffer.alloc(0);
  let tokenOutputIndexArray = Buffer.alloc(0);
  const tokenOutputLen = tokenOutputs.length;

  for (let i = 0; i < tokenOutputLen; i++) {
    const tokenOutput = tokenOutputs[i];
    const address = new bsv.Address(tokenOutput.address);
    const outputTokenAmount = BN.fromString(tokenOutput.amount, 10);

    const lockingScriptBuf = ftProto.getNewTokenScript(
      inputTokenScript.toBuffer(),
      address.hashBuffer,
      outputTokenAmount
    );
    let outputIndex = txComposer.appendOutput({
      lockingScript: bsv.Script.fromBuffer(lockingScriptBuf),
      satoshis: txComposer.getDustThreshold(lockingScriptBuf.length),
    });
    recervierArray = Buffer.concat([recervierArray, address.hashBuffer]);
    const tokenBuf = outputTokenAmount.toBuffer({
      endian: "little",
      size: 8,
    });
    receiverTokenAmountArray = Buffer.concat([
      receiverTokenAmountArray,
      tokenBuf,
    ]);
    const satoshiBuf = BN.fromNumber(
      txComposer.getOutput(outputIndex).satoshis
    ).toBuffer({
      endian: "little",
      size: 8,
    });
    tokenOutputSatoshiArray = Buffer.concat([
      tokenOutputSatoshiArray,
      satoshiBuf,
    ]);

    const indexBuf = BN.fromNumber(i).toBuffer({ endian: "little", size: 4 });
    tokenOutputIndexArray = Buffer.concat([tokenOutputIndexArray, indexBuf]);
  }

  //tx addOutput OpReturn
  let opreturnScriptHex = "";
  if (opreturnData) {
    const opreturnOutputIndex = txComposer.appendOpReturnOutput(opreturnData);
    opreturnScriptHex = txComposer
      .getOutput(opreturnOutputIndex)
      .script.toHex();
  }

  //The first round of calculations get the exact size of the final transaction, and then change again
  //Due to the change, the script needs to be unlocked again in the second round
  //let the fee to be exact in the second round
  for (let c = 0; c < 2; c++) {
    txComposer.clearChangeOutput();
    const changeOutputIndex = txComposer.appendChangeOutput(changeAddress);

    let unlockingContract0 = tokenLockContract.unlock({
      sig: new Sig(PLACE_HOLDER_SIG),
      ownerPubKey: new PubKey(PLACE_HOLDER_PUBKEY),
      unlockTime: new Int(oracleData.timestamp),
      rabinSig: {
        s: new Int(
          BN.fromString(
            Buffer.from(oracleData.signatures.rabin.signature, "hex")
              .reverse()
              .toString("hex"),
            16
          ).toString(10)
        ),
        padding: new Bytes(oracleData.signatures.rabin.padding),
      },
    });

    // let ret = unlockingContract0.verify({
    //   tx: txComposer.getTx(),
    //   inputIndex: 0,
    //   inputSatoshis: txComposer.getInput(0).output.satoshis,
    // });
    // if (ret.success == false) throw ret;
    txComposer
      .getInput(tokenLockInputIndex)
      .setScript(unlockingContract0.toScript() as bsv.Script);

    let rabinPubKeyArray = [];
    for (let j = 0; j < ftProto.SIGNER_VERIFY_NUM; j++) {
      const signerIndex = rabinPubKeyIndexArray[j];
      rabinPubKeyArray.push(tokenSigner.rabinPubKeyArray[signerIndex]);
    }
    tokenInputIndexs.forEach((inputIndex, idx) => {
      let tokenInput = tokenInputs[idx];
      let dataPartObj = ftProto.parseDataPart(
        tokenInput.lockingScript.toBuffer()
      );
      if (
        dataPartObj.rabinPubKeyHashArrayHash !=
        toHex(tokenSigner.rabinPubKeyHashArrayHash)
      ) {
        throw new Error("Invalid signers.");
      }
      const dataPart = ftProto.newDataPart(dataPartObj);

      const tokenContract = TokenFactory.createContract(
        tokenSigner.transferCheckCodeHashArray,
        tokenSigner.unlockContractCodeHashArray
      );

      tokenContract.setDataPart(toHex(dataPart));

      const unlockingContract = tokenContract.unlock({
        txPreimage: new SigHashPreimage(txComposer.getPreimage(inputIndex)),
        tokenInputIndex: idx, //和transfer不同，这里要根据tokenInputArray获取实际的
        prevouts: new Bytes(prevouts.toHex()),
        rabinMsg: rabinDatas[idx].rabinMsg,
        rabinPaddingArray: rabinDatas[idx].rabinPaddingArray,
        rabinSigArray: rabinDatas[idx].rabinSigArray,
        rabinPubKeyIndexArray,
        rabinPubKeyVerifyArray,
        rabinPubKeyHashArray: tokenSigner.rabinPubKeyHashArray,
        checkInputIndex: checkInputIndex,
        checkScriptTx: new Bytes(unlockCheckTxComposer.getRawHex()),
        nReceivers: tokenOutputLen,
        prevTokenAddress: new Bytes(
          toHex(tokenInput.preTokenAddress.hashBuffer)
        ),
        prevTokenAmount: new Int(tokenInput.preTokenAmount.toString(10)),
        lockContractInputIndex: tokenLockInputIndex,
        lockContractTx: new Bytes(tokenLockTxComposer.getRawHex()),
        operation: ftProto.OP_UNLOCK_FROM_CONTRACT,
      });

      txComposer
        .getInput(inputIndex)
        .setScript(unlockingContract.toScript() as bsv.Script);
    });

    let otherOutputs = Buffer.alloc(0);
    txComposer.getTx().outputs.forEach((output, index) => {
      if (index >= tokenOutputLen) {
        let outputBuf = output.toBufferWriter().toBuffer();
        let lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32LE(outputBuf.length);
        otherOutputs = Buffer.concat([otherOutputs, lenBuf, outputBuf]);
      }
    });

    let unlockingContract = unlockCheckContract.unlock({
      txPreimage: new SigHashPreimage(txComposer.getPreimage(checkInputIndex)),
      tokenScript: new Bytes(inputTokenScript.toHex()),
      prevouts: new Bytes(prevouts.toHex()),
      rabinMsgArray: checkRabinDatas.rabinMsgArray,
      rabinPaddingArray: checkRabinDatas.rabinPaddingArray,
      rabinSigArray: checkRabinDatas.rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray,
      rabinPubKeyHashArray: tokenSigner.rabinPubKeyHashArray,
      inputTokenAddressArray: new Bytes(toHex(inputTokenAddressArray)),
      inputTokenAmountArray: new Bytes(toHex(inputTokenAmountArray)),
      nOutputs: txComposer.getTx().outputs.length,
      tokenOutputIndexArray: new Bytes(toHex(tokenOutputIndexArray)),
      tokenOutputSatoshiArray: new Bytes(toHex(tokenOutputSatoshiArray)),
      otherOutputArray: new Bytes(toHex(otherOutputs)),
    });
    txComposer
      .getInput(checkInputIndex)
      .setScript(unlockingContract.toScript() as bsv.Script);
  }
  // txComposer.checkFeeRate();

  return {
    txComposer,
  };
}

createUnlockTx.estimateFee = function ({
  tokenInputs,
  tokenOutputs,
  tokenUnlockType,
  utxoMaxCount = 10,
  opreturnData,
}: {
  tokenInputs: TokenInput[];
  tokenOutputs: TokenOutput[];
  tokenUnlockType: TOKEN_UNLOCK_TYPE;
  utxoMaxCount?: number;
  opreturnData?: any;
}) {
  let p2pkhInputNum = utxoMaxCount;
  let stx = new SizeTransaction();

  let tokenLockingSize = TokenFactory.getLockingScriptSize();
  let tokenUnlockingSize = TokenFactory.calUnlockUnlockingScriptSize(
    utxoMaxCount,
    TokenLockFactory.createDummyTx().getRawHex(),
    tokenInputs.length,
    tokenOutputs.length,
    tokenUnlockType
  );

  stx.addInput(
    TokenLockFactory.calUnlockingScriptSize(),
    stx.getDustThreshold(TokenLockFactory.getLockingScriptSize())
  );

  for (let i = 0; i < tokenInputs.length; i++) {
    stx.addInput(tokenUnlockingSize, tokenInputs[i].satoshis);
  }

  for (let i = 0; i < p2pkhInputNum; i++) {
    stx.addP2PKHInput();
  }

  let otherOutputsLen = 0;
  if (opreturnData) {
    otherOutputsLen =
      otherOutputsLen +
      4 +
      8 +
      4 +
      bsv.Script.buildSafeDataOut(opreturnData).toBuffer().length;
  }

  otherOutputsLen = otherOutputsLen + 4 + 8 + 4 + 25;

  let otherOutputs = new Bytes(toHex(Buffer.alloc(otherOutputsLen, 0)));

  stx.addInput(
    TokenUnlockContractCheckFactory.calUnlockingScriptSize(
      tokenUnlockType,
      utxoMaxCount,
      tokenInputs.length,
      tokenOutputs.length,
      stx.inputs.length + 1,
      otherOutputs
    ),
    stx.getDustThreshold(
      TokenUnlockContractCheckFactory.getLockingScriptSize(tokenUnlockType)
    )
  );

  for (let i = 0; i < tokenOutputs.length; i++) {
    stx.addOutput(tokenLockingSize);
  }
  if (opreturnData) {
    stx.addOpReturnOutput(
      bsv.Script.buildSafeDataOut(opreturnData).toBuffer().length
    );
  }
  stx.addP2PKHOutput();
  return stx.getFee();
};
