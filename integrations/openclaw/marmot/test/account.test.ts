import { describe, expect, it } from "vitest";

import { resolveSingleAccount, type AccountListClient } from "../src/account.js";

const HEX32 = (b: string) => b.repeat(32);

function stubAccounts(
  accounts: Array<{ account_id_hex: string; label: string; local_signing: boolean }>,
): AccountListClient {
  return {
    async accountList() {
      return { type: "account_list", accounts };
    },
  } as unknown as AccountListClient;
}

describe("resolveSingleAccount", () => {
  it("auto-selects the sole local-signing account", async () => {
    const id = await resolveSingleAccount(
      stubAccounts([{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }]),
    );
    expect(id).toBe(HEX32("aa"));
  });

  it("throws when there is no local-signing account", async () => {
    await expect(
      resolveSingleAccount(
        stubAccounts([{ account_id_hex: HEX32("aa"), label: "agent", local_signing: false }]),
      ),
    ).rejects.toThrow();
  });

  it("throws when multiple accounts and none is pinned", async () => {
    await expect(
      resolveSingleAccount(
        stubAccounts([
          { account_id_hex: HEX32("aa"), label: "a", local_signing: true },
          { account_id_hex: HEX32("bb"), label: "b", local_signing: true },
        ]),
      ),
    ).rejects.toThrow();
  });

  it("validates and normalizes a pinned account id", async () => {
    const id = await resolveSingleAccount(
      stubAccounts([
        { account_id_hex: HEX32("aa"), label: "a", local_signing: true },
        { account_id_hex: HEX32("bb"), label: "b", local_signing: true },
      ]),
      `0x${HEX32("bb").toUpperCase()}`,
    );
    expect(id).toBe(HEX32("bb"));
  });

  it("throws when the pinned account is absent", async () => {
    await expect(
      resolveSingleAccount(
        stubAccounts([{ account_id_hex: HEX32("aa"), label: "a", local_signing: true }]),
        HEX32("cc"),
      ),
    ).rejects.toThrow();
  });
});
