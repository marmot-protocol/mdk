import { AgentControlError, normalizeHex } from "../src/client.js";

export interface RecordedEncryptedKind9Post {
  accountIdHex: string;
  groupIdHex: string;
  text: string;
  replyToMessageIdHex: string | null;
  idempotencyKey?: string;
  messageIdsHex: string[];
}

/**
 * Contract-faithful send_final test double: a completed key + matching request
 * fingerprint returns the first durable ids without publishing another kind-9.
 * It can lose the first success response to model a timeout/disconnect after the
 * connector has committed the encrypted post and persisted its dedup record.
 */
export class DeduplicatingFinalConnector {
  readonly encryptedKind9Posts: RecordedEncryptedKind9Post[] = [];

  private readonly completed = new Map<
    string,
    { fingerprint: string; response: { type: "final_sent"; message_ids_hex: string[] } }
  >();
  private loseNextSuccessResponse = false;

  armPostSuccessDisconnect(): void {
    this.loseNextSuccessResponse = true;
  }

  async sendFinal(
    accountIdHex: string,
    groupIdHex: string,
    text: string,
    replyToMessageIdHex?: string | null,
    idempotencyKey?: string,
  ): Promise<{ type: "final_sent"; message_ids_hex: string[] }> {
    const replyTo = replyToMessageIdHex ?? null;
    const fingerprint = JSON.stringify([
      normalizeHex(accountIdHex, "accountIdHex"),
      normalizeHex(groupIdHex, "groupIdHex"),
      text,
      replyTo == null ? null : normalizeHex(replyTo, "replyToMessageIdHex"),
    ]);
    const completed = idempotencyKey ? this.completed.get(idempotencyKey) : undefined;
    if (completed?.fingerprint === fingerprint) {
      return completed.response;
    }

    const messageIdsHex = [this.nextMessageIdHex()];
    const response = { type: "final_sent" as const, message_ids_hex: messageIdsHex };
    this.encryptedKind9Posts.push({
      accountIdHex,
      groupIdHex,
      text,
      replyToMessageIdHex: replyTo,
      idempotencyKey,
      messageIdsHex,
    });
    if (idempotencyKey && !completed) {
      this.completed.set(idempotencyKey, { fingerprint, response });
    }

    if (this.loseNextSuccessResponse) {
      this.loseNextSuccessResponse = false;
      throw new AgentControlError("connection closed after durable send", {
        code: "connection_closed",
        retryable: true,
      });
    }
    return response;
  }

  private nextMessageIdHex(): string {
    return (this.encryptedKind9Posts.length + 1).toString(16).padStart(64, "0");
  }
}
