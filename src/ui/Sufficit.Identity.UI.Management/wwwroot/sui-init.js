// Sufficit.Blazor.UI applies computed styles through CSSOM so they survive a
// strict CSP (style-src-attr 'none'). Blazor would start that initializer on
// its own, but this host loads blazor.web.js from its own path without the
// static-assets manifest, so the initializer list never reaches the page; the
// library ships the same code under a stable name for this case.
import { startSuiStyle } from '/_content/Sufficit.Blazor.UI/sui-style.js';

startSuiStyle();
