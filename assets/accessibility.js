// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — Keyboard access to documentation controls

/**
 * Expose the theme's header toggles and horizontally scrollable tables to keyboard users.
 * @module
 */

const controls = /** @type {NodeListOf<HTMLLabelElement>} */ (
  document.querySelectorAll(
    '.md-header__button[for="__drawer"], .md-header__button[for="__search"]',
  )
);
for (const label of controls) {
  const toggle = /** @type {HTMLInputElement} */ (label.control);
  label.tabIndex = 0;
  label.setAttribute("role", "button");
  label.setAttribute(
    "aria-label",
    label.htmlFor === "__drawer" ? "Navigation menu" : "Search",
  );

  const reflectExpanded = () =>
    label.setAttribute("aria-expanded", String(toggle.checked));
  reflectExpanded();
  toggle.addEventListener("change", reflectExpanded);
  if (label.htmlFor === "__drawer") {
    configureDrawer(label, toggle);
  } else {
    configureSearch(label, toggle);
  }
  label.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      event.stopPropagation();
      label.click();
    }
  });
}

/**
 * Preserve the desktop search field and keep closed mobile search out of tab order.
 * @param {HTMLLabelElement} label
 * @param {HTMLInputElement} toggle
 */
function configureSearch(label, toggle) {
  const desktop = window.matchMedia("screen and (min-width: 60em)");
  const input = /** @type {HTMLInputElement} */ (
    document.querySelector(".md-search__input")
  );
  const output = /** @type {HTMLElement} */ (
    document.querySelector(".md-search__output")
  );
  const update = () => {
    input.tabIndex = toggle.checked || desktop.matches ? 0 : -1;
    output.inert = !toggle.checked;
  };
  update();
  toggle.addEventListener("change", update);
  desktop.addEventListener("change", update);
  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key === "Escape" && toggle.checked && !desktop.matches) {
        requestAnimationFrame(() => label.focus());
      }
    },
    { capture: true },
  );
}

/**
 * Make Material's mobile navigation drawer modal while it is open.
 * @param {HTMLLabelElement} label
 * @param {HTMLInputElement} toggle
 */
function configureDrawer(label, toggle) {
  const mobile = window.matchMedia("screen and (max-width: 76.234375em)");
  /** @type {Set<HTMLElement>} */
  const background = new Set();
  /** @type {HTMLElement | undefined} */
  let active;

  toggle.addEventListener("change", () => {
    if (!toggle.checked) {
      if (active) {
        for (const element of background) {
          element.inert = false;
        }
        background.clear();
        active.removeAttribute("role");
        active.removeAttribute("aria-label");
        active.removeAttribute("aria-modal");
        active = undefined;
        if (mobile.matches) {
          label.focus({ preventScroll: true });
        }
      }
      return;
    }

    const drawer = /** @type {HTMLElement} */ (
      document.querySelector(".md-sidebar--primary")
    );
    let close = /** @type {HTMLButtonElement | null} */ (
      drawer.querySelector(".md-drawer-close")
    );
    if (!close) {
      const button = document.createElement("button");
      button.className = "md-drawer-close";
      button.type = "button";
      button.textContent = "Close navigation";
      button.addEventListener("click", () => toggle.click());
      const navigation = /** @type {HTMLElement} */ (
        drawer.querySelector(".md-nav--primary")
      );
      navigation.prepend(button);
      close = button;
    }
    drawer.setAttribute("role", "dialog");
    drawer.setAttribute("aria-label", "Navigation menu");
    drawer.setAttribute("aria-modal", "true");
    active = drawer;
    /** @type {HTMLElement | null} */
    let branch = drawer;
    while (branch !== document.body && branch.parentElement) {
      for (const sibling of branch.parentElement.children) {
        if (
          sibling instanceof HTMLElement &&
          sibling !== branch &&
          !sibling.inert &&
          !sibling.matches('label[for="__drawer"].md-overlay, .md-toggle')
        ) {
          sibling.inert = true;
          background.add(sibling);
        }
      }
      branch = branch.parentElement;
    }
    close.focus();
  });

  mobile.addEventListener("change", () => {
    if (!mobile.matches && toggle.checked) {
      toggle.click();
    }
  });

  document.addEventListener(
    "keydown",
    (event) => {
      if (!active) {
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        toggle.click();
        return;
      }
      if (event.key !== "Tab") {
        return;
      }
      const stops = [
        ...active.querySelectorAll(".md-drawer-close, a[href]"),
      ].filter(
        (element) =>
          element.getClientRects().length > 0 &&
          getComputedStyle(element).visibility === "visible",
      );
      const first = /** @type {HTMLElement} */ (stops[0]);
      const last = /** @type {HTMLElement} */ (stops.at(-1));
      if (document.activeElement === (event.shiftKey ? first : last)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      }
    },
    { capture: true },
  );
}

const tableResize = new ResizeObserver((entries) => {
  for (const { target } of entries) {
    const region = /** @type {HTMLElement} */ (target);
    region.tabIndex = region.scrollWidth > region.clientWidth ? 0 : -1;
  }
});

const pageChanges =
  /** @type {Window & {document$?: {subscribe(callback: () => void): void}}} */ (
    window
  ).document$;
pageChanges?.subscribe(() => {
  const skipLinks = /** @type {NodeListOf<HTMLAnchorElement>} */ (
    document.querySelectorAll("a.md-skip")
  );
  for (const link of skipLinks) {
    const destination = document.getElementById(
      decodeURIComponent(link.hash.slice(1)),
    );
    if (destination) {
      destination.tabIndex = -1;
      link.onclick = (event) => {
        event.preventDefault();
        event.stopPropagation();
        window.history.pushState(window.history.state, "", link.hash);
        destination.scrollIntoView();
        destination.focus({ preventScroll: true });
      };
    }
  }
  tableResize.disconnect();
  for (const region of document.querySelectorAll(".md-typeset__scrollwrap")) {
    region.setAttribute("role", "group");
    region.setAttribute("aria-label", "Scrollable table");
    tableResize.observe(region);
  }
});
