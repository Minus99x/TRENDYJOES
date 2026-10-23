/**
 * Objective 35F — deterministic, offline DOM integration contract for the
 * Main35/Night35E reconciled preview. This is NOT a browser or Shopify test.
 * Fail closed on changed Liquid seams, inaccessible references and commerce.
 */
const fail = code => { throw new Error(code); };
const sectionPath = 'sections/tj-static-preview-34i.liquid';
const scriptName = 'tj34i-demo-static-preview.js';
const styleNames = ['tj34i-demo-studio.css', 'tj34i-demo-static-preview.css'];
const requiredIds = [
  'tj34i-root','tj34i-product','tj34i-surface','tj34i-concept-color',
  'tj34i-concept-size','tj34i-text-entry','tj34i-text-help','tj34i-add-text',
  'tj34i-layers','tj34i-review-preview','tj34i-review-help',
  'tj34i-preview-summary-panel','tj34i-concept-a11y-summary',
  'tj34i-stage','tj34i-stage-3d','tj34i-mode-2d','tj34i-mode-3d'
];
const exactly = (text, expression, count, code) => {
  if ([...text.matchAll(expression)].length !== count) fail(code);
};
const attr = (tag, name) => {
  const match = tag.match(new RegExp(`(?:^|\\s)${name}="([^"]*)"`, 'i'));
  return match?.[1] ?? null;
};
const hasBooleanAttr = (tag, name) => new RegExp(`(?:^|\\s)${name}(?:\\s|>|$)`, 'i').test(tag.replace(/=\"[^\"]*\"/g, '=\"\"'));
const asset = (name) => `assets/${name}`;

export function validateOfflineMainDom({files}) {
  if (!(files instanceof Map) || files.size !== 13) fail('DOM_ASSET_GRAPH_INVALID');
  const section = files.get(sectionPath);
  if (typeof section !== 'string' || section.length > 262144) fail('DOM_SECTION_INVALID');
  const paths = [...files.keys()];
  if (new Set(paths).size !== paths.length || paths.some(p => !/^(?:assets\/tj34i-[a-z0-9-]+\.(?:css|js)|sections\/tj-static-preview-34i\.liquid)$/.test(p))) fail('DOM_ASSET_PATH_INVALID');
  for (const [p, value] of files) if (typeof value !== 'string' || value.length > 1024 * 1024) fail('DOM_ASSET_CONTENT_INVALID');
  const comment = /\{% comment %\}[\s\S]*?\{% endcomment %\}/g;
  const schema = /\{% schema %\}[\s\S]*?\{% endschema %\}/g;
  exactly(section, comment, 1, 'DOM_LIQUID_COMMENT_INVALID');
  exactly(section, schema, 1, 'DOM_LIQUID_SCHEMA_INVALID');
  const styleTag = /\{\{ '([^']+)' \| asset_url \| stylesheet_tag \}\}/g;
  const styles = [...section.matchAll(styleTag)].map(m => m[1]);
  if (styles.length !== 2 || styles.some((s, i) => s !== styleNames[i])) fail('DOM_STYLESHEET_GRAPH_INVALID');
  const scriptTag = /<script type="module" src="\{\{ '([^']+)' \| asset_url \}\}"><\/script>/g;
  const scripts = [...section.matchAll(scriptTag)].map(m => m[1]);
  if (scripts.length !== 1 || scripts[0] !== scriptName) fail('DOM_SCRIPT_GRAPH_INVALID');
  for (const name of [...styles, ...scripts]) if (!files.has(asset(name))) fail('DOM_ASSET_MISSING');
  const markup = section.replace(comment, '').replace(schema, '').replace(styleTag, '')
    .replace(scriptTag, (_, name) => `<script type="module" src="/assets/${name}"></script>`);
  if (markup.includes('{%') || markup.includes('{{') || /<\/?(?:form|iframe|object|embed|base|meta|link)\b/i.test(markup)) fail('DOM_UNTRUSTED_MARKUP');
  if (/<script\b(?![^>]*src="\/assets\/tj34i-demo-static-preview\.js")/i.test(markup) || /\bon[a-z]+\s*=/i.test(markup)) fail('DOM_EXECUTABLE_MARKUP');
  if (/<input\b[^>]*\btype\s*=\s*["']?(?:file|submit|image)\b/i.test(markup) || /\b(?:action|formaction)\s*=/i.test(markup)) fail('DOM_COMMERCE_FORBIDDEN');
  if (/\b(?:href|src)\s*=\s*["'](?:https?:|\/\/|\/(?!assets\/tj34i-))/i.test(markup)) fail('DOM_EXTERNAL_REFERENCE');
  const tags = [...markup.matchAll(/<([a-z][\w-]*)\b([^<>]*)>/gi)];
  const ids = new Set();
  const controls = new Map();
  const refs = [];
  let externalAnchorCount = 0;
  for (const [, type, attrs] of tags) {
    const normalizedAttrs = attrs.replace(/=\"[^\"]*\"/g, '=\"\"');
    const names = [...normalizedAttrs.matchAll(/(?:^|\s)([a-z][\w:-]*)(?=\s|=|$)/gi)].map(x => x[1].toLowerCase());
    if (new Set(names).size !== names.length) fail('DOM_DUPLICATE_ATTRIBUTE');
    const id = attr(attrs, 'id');
    if (id) {
      if (ids.has(id)) fail('DOM_DUPLICATE_ID');
      ids.add(id);
      controls.set(id, {type: type.toLowerCase(), attrs});
    }
    for (const name of ['aria-describedby','aria-labelledby','for']) {
      const value = attr(attrs, name);
      if (value !== null) {
        if (!value.trim()) fail('DOM_EMPTY_REFERENCE');
        refs.push(...value.split(/\s+/).map(v => [v, name]));
      }
    }
    if (type.toLowerCase() === 'a') {
      const href = attr(attrs, 'href');
      if (href !== '#tj-try-studio') fail('DOM_LINK_NOT_APPROVED');
      externalAnchorCount++;
    }
    if (type.toLowerCase() === 'button' && attr(attrs, 'type') !== 'button' && !hasBooleanAttr(attrs, 'disabled')) fail('DOM_IMPLICIT_SUBMIT_BUTTON');
  }
  for (const id of requiredIds) if (!ids.has(id)) fail('DOM_REQUIRED_CONTROL_MISSING');
  for (const [id, name] of refs) if (!ids.has(id)) fail(name === 'for' ? 'DOM_LABEL_TARGET_MISSING' : 'DOM_ARIA_TARGET_MISSING');
  if (externalAnchorCount !== 1) fail('DOM_MAIN_ARTWORK_LINK_INVALID');
  const review = controls.get('tj34i-review-preview');
  if (!hasBooleanAttr(review.attrs, 'disabled')) fail('DOM_REVIEW_INITIAL_GATE_MISSING');
  const checkout = tags.find(([, type, attrs]) => type.toLowerCase() === 'button' && /disabled-checkout/.test(attr(attrs, 'class') || ''));
  if (!checkout || !hasBooleanAttr(checkout[2], 'disabled')) fail('DOM_CHECKOUT_GATE_MISSING');
  if (controls.get('tj34i-stage-3d').type !== 'canvas' || controls.get('tj34i-stage').type !== 'svg') fail('DOM_2D_3D_SURFACE_MISSING');
  const studioCss = files.get(asset(styleNames[0]));
  const staticCss = files.get(asset(styleNames[1]));
  if (/@import\b|url\s*\(/i.test(studioCss + staticCss)) fail('DOM_EXTERNAL_STYLE_FORBIDDEN');
  if (!studioCss.includes('.masthead h2') || !studioCss.includes('a:focus-visible') || !staticCss.includes(':focus-visible') || !studioCss.includes('@media')) fail('DOM_STYLE_ACCESSIBILITY_MISSING');
  return Object.freeze({markup, idCount: ids.size, linkedReferences: refs.length, externalMainAnchor: '#tj-try-studio',
    stylesheetCount: styles.length, moduleCount: scripts.length, assetCount: files.size,
    nativeBrowserVerified: false, shopifyWrites: 0});
}

/** Reject a stale or partially reconciled on-disk candidate before serving. */
export async function verifyOfflineMainAssetBytes(files, readAsset) {
  validateOfflineMainDom({files});
  if (typeof readAsset !== 'function') fail('DOM_ASSET_READER_REQUIRED');
  for (const [path, expected] of files) {
    let actual;
    try { actual = await readAsset(path); } catch { fail('DOM_CANDIDATE_ASSET_MISSING:' + path); }
    if (typeof actual !== 'string' || actual !== expected) fail('DOM_CANDIDATE_ASSET_DRIFT:' + path);
  }
  return Object.freeze({verifiedAssets:files.size,shopifyWrites:0});
}
