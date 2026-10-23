// Branding preview: sets the theme variables through CSSOM, which the CSP
// does not govern, instead of an inline style attribute, which it blocks.
export function setVariables(element, variables) {
    if (!element) {
        return;
    }

    for (const [name, value] of Object.entries(variables)) {
        if (name.startsWith("--preview-")) {
            element.style.setProperty(name, value);
        }
    }
}
