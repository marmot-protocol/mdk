// Append-only text tracker. Marmot's `stream_append` carries only the suffix
// added since the last update, so progressive gateway updates (which arrive as
// growing full-text snapshots) must be reduced to append-only deltas. If an
// update is not an extension of what we already streamed, we cannot represent
// it as an append and the caller must fall back to a plain final send.
//
// Port of the Python shim's `AppendOnlyTextState` (integrations/hermes/...).

export class NonAppendOnlyUpdateError extends Error {
  constructor(message = "Marmot stream update is not append-only") {
    super(message);
    this.name = "NonAppendOnlyUpdateError";
  }
}

export class AppendOnlyText {
  private text = "";

  get current(): string {
    return this.text;
  }

  /**
   * Return the suffix that extends the previously-seen text to `next`, and
   * advance the tracked text. Throws {@link NonAppendOnlyUpdateError} if `next`
   * is not a prefix-extension of the current text.
   */
  suffixFor(next: string): string {
    const value = next ?? "";
    if (!value.startsWith(this.text)) {
      throw new NonAppendOnlyUpdateError();
    }
    const suffix = value.slice(this.text.length);
    this.text = value;
    return suffix;
  }
}
