import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBar } from "../components/ui";

describe("SeverityBar", () => {
  it("draws one segment per severity with width proportional to the count", () => {
    const { container } = render(<SeverityBar counts={{ high: 3, medium: 1 }} />);
    const rects = [...container.querySelectorAll("rect")];
    const high = rects.find((r) => r.classList.contains("fill-high"))!;
    expect(high.getAttribute("width")).toBe("75");
    expect(screen.getByText("3 high")).toBeTruthy();
    expect(container.querySelector("[style]")).toBeNull(); // no inline styles (CSP)
  });

  it("says when there is nothing to show", () => {
    render(<SeverityBar counts={{}} />);
    expect(screen.getByText("No findings")).toBeTruthy();
  });
});
