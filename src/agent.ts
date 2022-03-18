import { getAddress } from '@ethersproject/address';
import {
  Finding,
  HandleTransaction,
  TransactionEvent,
  FindingSeverity,
  FindingType
} from 'forta-agent'
// import { Convo } from '@theconvospace/sdk';
import etherscanLabels from "./etherscan";

const handleTransaction: HandleTransaction = async (txEvent: TransactionEvent) => {
  const findings: Finding[] = []
  // const convoInstance = new Convo('CSCpPwHnkB3niBJiUjy92YGP6xVkVZbWfK8xriDO');
  // const computeConfig = {
  //   CNVSEC_ID: "",
  //   polygonMainnetRpc: '',
  //   etherumMainnetRpc: '',
  //   avalancheMainnetRpc: '',
  //   maticPriceInUsd: 0,
  //   etherumPriceInUsd: 0,
  //   deepdaoApiKey: '',
  //   etherscanApiKey: '',
  //   polygonscanApiKey: '',
  //   DEBUG: false
  // };
  // let adds = Object.keys(txEvent.addresses);
  // let promiseArray = await Promise.allSettled(adds.map((add)=>{
  //   return convoInstance.omnid.adaptors.getEtherscanData(add, computeConfig)
  // }))

  let adds = Object.keys(txEvent.addresses);
  let promiseArray = await Promise.allSettled(adds.map((add)=>{
    let labels = etherscanLabels[getAddress(add)]; // identify phish, hack, fake, heist.
    return Boolean(labels) === true ? labels : false;
  }))

  for (let index = 0; index < promiseArray.length; index++) {
    let result = promiseArray[index];
    if (result.status === 'fulfilled' && Boolean(result.value) === true){
      findings.push(
        Finding.fromObject({
          name: "Malicious Address",
          description: `Transaction involving a Malicious address: ${adds[index]}`,
          alertId: "OMNID-1",
          type: FindingType.Suspicious,
          severity: FindingSeverity.High,
          metadata: {
            address: adds[index],
            data: JSON.stringify(result.value),
          }
        }
      ))
    }
  }

  return findings
}

// const handleBlock: HandleBlock = async (blockEvent: BlockEvent) => {
//   const findings: Finding[] = [];
//   // detect some block condition
//   return findings;
// }

export default {
  handleTransaction,
  // handleBlock
}
