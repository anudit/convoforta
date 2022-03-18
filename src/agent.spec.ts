import {
  FindingType,
  FindingSeverity,
  Finding,
  HandleTransaction,
  createTransactionEvent
} from "forta-agent"
import agent from "./agent"

describe("Malicious addresstest", () => {
  let handleTransaction: HandleTransaction

  const createTxEventWithAddresses = (addresses: string[]) => createTransactionEvent({
    transaction: {} as any,
    receipt: {} as any,
    block: {} as any,
    addresses: addresses as any,
  })

  beforeAll(() => {
    handleTransaction = agent.handleTransaction
  })

  describe("handleTransaction", () => {
    it("returns empty findings if no malicious interactions found.", async () => {
      const txEvent = createTxEventWithAddresses(["0x2819c144d5946404c0516b6f817a960db37d4929"])

      const findings = await handleTransaction(txEvent)

      expect(findings).toStrictEqual([])
    })

    it("returns findings if malicious interactions found.", async () => {
      const txEvent = createTxEventWithAddresses(["0x9f26aE5cd245bFEeb5926D61497550f79D9C6C1c"])

      const findings = await handleTransaction(txEvent)

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Malicious Address",
          description: `Transaction involving a Malicious address: 0x9f26ae5cd245bfeeb5926d61497550f79d9c6c1c`,
          alertId: "OMIND-1",
          type: FindingType.Suspicious,
          severity: FindingSeverity.High,
          metadata: {
            address: "0x9f26ae5cd245bfeeb5926d61497550f79d9c6c1c",
            data: "[\"heist\",\"Akropolis Hacker 1\",\"Akropolis Hacker 1\"]"
          }
        }),

      ])
    })
  })
})
