import { describe, expect, it } from "vitest";

import { AppendOnlyText, NonAppendOnlyUpdateError } from "../src/append-only.js";

describe("AppendOnlyText", () => {
  it("returns the growing suffix across updates", () => {
    const state = new AppendOnlyText();
    expect(state.suffixFor("hel")).toBe("hel");
    expect(state.suffixFor("hello")).toBe("lo");
    expect(state.suffixFor("hello world")).toBe(" world");
    expect(state.current).toBe("hello world");
  });

  it("returns an empty suffix for an unchanged update", () => {
    const state = new AppendOnlyText();
    state.suffixFor("hello");
    expect(state.suffixFor("hello")).toBe("");
  });

  it("throws when an update is not an extension", () => {
    const state = new AppendOnlyText();
    state.suffixFor("hello");
    expect(() => state.suffixFor("goodbye")).toThrow(NonAppendOnlyUpdateError);
  });

  it("treats nullish text as empty", () => {
    const state = new AppendOnlyText();
    expect(state.suffixFor(undefined as unknown as string)).toBe("");
  });
});
