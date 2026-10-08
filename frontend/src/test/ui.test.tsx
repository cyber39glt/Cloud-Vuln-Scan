import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBar } from "../components/ui";

describe("SeverityBar", () => {
  it("draws one segment per severity with width proportional to the count", () => {
    const { container } = render(<SeverityBar counts={{ high: 3, medium: 1 }} />);
    const rects = [...container.querySelectorAll("rect")];
    const high = rects.find((r) => r.classList.contains("fill-high"))!;
    const medium = rects.find((r) => r.classList.contains("fill-medium"))!;
    // 320px default width, minus one 2px gap, split 3:1.
    expect(Number(high.getAttribute("width"))).toBeCloseTo(238.5);
    expect(Number(medium.getAttribute("width"))).toBeCloseTo(79.5);
    expect(Number(medium.getAttribute("x"))).toBeCloseTo(240.5);
    expect(screen.getByText("3 high")).toBeTruthy();
    expect(container.querySelector("[style]")).toBeNull(); // no inline styles (CSP)
  });

  it("says when there is nothing to show", () => {
    render(<SeverityBar counts={{}} />);
    expect(screen.getByText("No findings")).toBeTruthy();
  });
});
