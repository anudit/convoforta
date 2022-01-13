import {
  Finding,
  HandleTransaction,
  TransactionEvent,
  FindingSeverity,
  FindingType
} from 'forta-agent'
import { Convo } from '@theconvospace/sdk';

// report finding if any addresses involved in transaction have a negative TrustScore (Malicious)
const handleTransaction: HandleTransaction = async (txEvent: TransactionEvent) => {
  const findings: Finding[] = []
  const convoInstance = new Convo('CSCpPwHnkB3niBJiUjy92YGP6xVkVZbWfK8xriDO');

  let adds = Object.keys(txEvent.addresses);
  let promiseArray = await Promise.allSettled(adds.map((add)=>{
    return convoInstance.omnid.getTrustScore(add)
  }))

  for (let index = 0; index < promiseArray.length; index++) {
    const result = promiseArray[index];
    if (result.status === 'fulfilled' && result.value?.score <= 0){
      findings.push(
        Finding.fromObject({
          name: "Malicious Address",
          description: `Transaction involving a Malicious address: ${result.value?._id}`,
          alertId: "OMNID-1",
          type: FindingType.Suspicious,
          severity: FindingSeverity.High,
          metadata: {
            address: result.value?._id,
            score: result.value?.score,
            graph: result.value
          }
        }
      ))
    }
  }

  return findings
}

export default {
  handleTransaction
}
