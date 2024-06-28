import { ethers } from "hardhat";
import { HardhatEthersProvider } from "@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider";
import {
  PolygonZkEVMDeployer,
} from "../../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers"
import { expect } from "chai";

const deployerAddress = "0x4c1665d6651ecEfa59B9B3041951608468b18891";

export async function create2Deployment(
  polgonZKEVMDeployerContract: PolygonZkEVMDeployer,
  salt: string,
  deployTransaction: string,
  dataCall: string | null,
  deployer: HardhatEthersSigner,
  hardcodedGasLimit: bigint | null
) {
  // Encode deploy transaction
  const hashInitCode = ethers.solidityPackedKeccak256(["bytes"], [deployTransaction]);

  // Precalculate create2 address
  const precalculatedAddressDeployed = ethers.getCreate2Address(
    polgonZKEVMDeployerContract.target as string,
    salt,
    hashInitCode
  );
  const amount = 0;

  if ((await deployer.provider.getCode(precalculatedAddressDeployed)) !== "0x") {
    return [precalculatedAddressDeployed, false];
  }

  if (dataCall) {
    // Deploy using create2 and call
    if (hardcodedGasLimit) {
      const populatedTransaction =
        await polgonZKEVMDeployerContract.deployDeterministicAndCall.populateTransaction(
          amount,
          salt,
          deployTransaction,
          dataCall
        );
      populatedTransaction.gasLimit = hardcodedGasLimit;
      await (await deployer.sendTransaction(populatedTransaction)).wait();
    } else {
      await (
        await polgonZKEVMDeployerContract.deployDeterministicAndCall(amount, salt, deployTransaction, dataCall)
      ).wait();
    }
  } else {
    // Deploy using create2
    if (hardcodedGasLimit) {
      const populatedTransaction = await polgonZKEVMDeployerContract.deployDeterministic.populateTransaction(
        amount,
        salt,
        deployTransaction
      );
      populatedTransaction.gasLimit = hardcodedGasLimit;
      await (await deployer.sendTransaction(populatedTransaction)).wait();
    } else {
      await (await polgonZKEVMDeployerContract.deployDeterministic(amount, salt, deployTransaction)).wait();
    }
  }
  return [precalculatedAddressDeployed, true];
}

async function getZkEVMDeployerContract() {
  const gasPriceKeylessDeployment = "100"; // 100 gweis

  const signer = await ethers.getSigner(deployerAddress);
  const PolgonZKEVMDeployerFactory = await ethers.getContractFactory("PolygonZkEVMDeployer", signer);

  const deployTxZKEVMDeployer = (await PolgonZKEVMDeployerFactory.getDeployTransaction(deployerAddress)).data;

  const gasLimit = BigInt(1000000); // Put 1 Million, aprox 650k are necessary
  const gasPrice = BigInt(ethers.parseUnits(gasPriceKeylessDeployment, "gwei"));

  const signature = {
    v: 27,
    r: "0x5ca1ab1e0", // Equals 0x00000000000000000000000000000000000000000000000000000005ca1ab1e0
    s: "0x5ca1ab1e", // Equals 0x000000000000000000000000000000000000000000000000000000005ca1ab1e
  };
  const tx = ethers.Transaction.from({
    to: null, // bc deployment transaction, "to" is "0x"
    nonce: 0,
    value: 0,
    gasLimit: gasLimit,
    gasPrice: gasPrice,
    data: deployTxZKEVMDeployer,
    type: 0, // legacy transaction
    signature,
  });

  const totalEther = gasLimit * gasPrice; // 0.1 ether
  const signerProvider = signer.provider as HardhatEthersProvider;
  // Check if it's already deployed
  const zkEVMDeployerAddress = ethers.getCreateAddress({ from: tx.from as string, nonce: tx.nonce });
  if ((await signerProvider.getCode(zkEVMDeployerAddress)) !== "0x") {
    const zkEVMDeployerContract = PolgonZKEVMDeployerFactory.attach(zkEVMDeployerAddress) as PolygonZkEVMDeployer;
    expect(await zkEVMDeployerContract.owner()).to.be.equal(signer.address);
    return zkEVMDeployerContract;
  }

  // Fund keyless deployment
  const params = {
    to: tx.from,
    value: totalEther,
  };
  await (await signer.sendTransaction(params)).wait();

  // Deploy zkEVMDeployer

  await (await signerProvider.broadcastTransaction(tx.serialized)).wait();

  return (await PolgonZKEVMDeployerFactory.attach(
    zkEVMDeployerAddress
  )) as PolygonZkEVMDeployer;

}

async function deployBridge() {
  const deployer = await ethers.getSigner(deployerAddress);
  const zkEVMDeployerContract = await getZkEVMDeployerContract();
  const salt = "0x0000000000000000000000000000000000000000000000000000000000000000"; // salt mock

  const polygonZkEVMBridgeFactory = await ethers.getContractFactory("PolygonZkEVMBridgeV2", deployer);
  const deployTransactionBridge = (await polygonZkEVMBridgeFactory.getDeployTransaction()).data;

  // Mandatory to override the gasLimit since the estimation with create are mess up D:
  const overrideGasLimit = BigInt(5500000);
  console.log("Create2 Deployment")
  const [bridgeImplementationAddress, deployed] = await create2Deployment(
    zkEVMDeployerContract,
    salt,
    deployTransactionBridge,
    null,
    deployer,
    overrideGasLimit
  );
  console.log("Create2 Deployment done")
  return bridgeImplementationAddress;
}

deployBridge();