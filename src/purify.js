import * as TAGS from './tags.js';
import * as ATTRS from './attrs.js';
import * as EXPRESSIONS from './regexp.js';
import {
  addToSet,
  clone,
  create,
  freeze,
  arrayForEach,
  arrayIndexOf,
  arrayPop,
  arrayPush,
  stringMatch,
  stringReplace,
  stringToLowerCase,
  stringToString,
  stringIndexOf,
  stringTrim,
  regExpTest,
  typeErrorCreate,
  lookupAccessor,
  lookupGetter,
} from './utils.js';

const getGlobal = () => (typeof window === 'undefined' ? null : window);

/**
 * Creates a no-op policy for internal use only.
 * Don't export this function outside this module!
 * @param {?TrustedTypePolicyFactory} trustedTypes The policy factory.
 * @param {Document} document The document object (to determine policy name suffix)
 * @return {?TrustedTypePolicy} The policy created (or null, if Trusted Types
 * are not supported).
 */
const _createTrustedTypesPolicy = function (trustedTypes, document) {
  if (
    typeof trustedTypes !== 'object' ||
    typeof trustedTypes.createPolicy !== 'function'
  ) {
    return null;
  }

  // Allow the callers to control the unique policy name
  // by adding a data-tt-policy-suffix to the script element with the DOMPurify.
  // Policy creation with duplicate names throws in Trusted Types.
  let suffix = null;
  const ATTR_NAME = 'data-tt-policy-suffix';
  if (
    document.currentScript &&
    document.currentScript.hasAttribute(ATTR_NAME)
  ) {
    suffix = document.currentScript.getAttribute(ATTR_NAME);
  }

  const policyName = 'dompurify' + (suffix ? '#' + suffix : '');

  try {
    return trustedTypes.createPolicy(policyName, {
      createHTML(html) {
        return html;
      },
      createScriptURL(scriptUrl) {
        return scriptUrl;
      },
    });
  } catch (_) {
    // Policy creation failed (most likely another DOMPurify script has
    // already run). Skip creating the policy, as this will only cause errors
    // if TT are enforced.
    console.warn(
      'TrustedTypes policy ' + policyName + ' could not be created.'
    );
    return null;
  }
};

function createDOMPurify(window = getGlobal()) {
  const DOMPurify = (root) => createDOMPurify(root);

  /**
   * Version label, exposed for easier checks
   * if DOMPurify is up to date or not
   */
  DOMPurify.version = VERSION;

  /**
   * Array of elements that DOMPurify removed during sanitation.
   * Empty if nothing was removed.
   */
  DOMPurify.removed = [];

  if (!window || !window.document || window.document.nodeType !== 9) {
    // Not running in a browser, provide a factory function
    // so that you can pass your own Window
    DOMPurify.isSupported = false;

    return DOMPurify;
  }

  const originalDocument = window.document;

  let { document } = window;
  const {
    HTMLTemplateElement,
    Node,
    Element,
    NodeFilter,
    DOMParser,
    trustedTypes,
  } = window;

  const ElementPrototype = Element.prototype;

  /* Read DOM properties through their prototype getters, which a clobbering
     form descendant can not shadow and which work on nodes of any realm.
     Engines that keep these properties on the instance (Safari < 10,
     Chrome < 43) have no such getter: read the instance property there.
     lookupGetter's stub would return null for every node and make every
     form look clobbered. */
  const lookupNodeGetter = function (object, prop) {
    return lookupAccessor(object, prop) || ((node) => node[prop]);
  };

  const cloneNode = lookupGetter(ElementPrototype, 'cloneNode');
  const getNextSibling = lookupGetter(ElementPrototype, 'nextSibling');
  const getChildNodes = lookupNodeGetter(ElementPrototype, 'childNodes');
  const getParentNode = lookupGetter(ElementPrototype, 'parentNode');
  const getAttributes = lookupNodeGetter(ElementPrototype, 'attributes');
  const getNodeType =
    Node && Node.prototype
      ? lookupNodeGetter(Node.prototype, 'nodeType')
      : null;
  const getNodeName =
    Node && Node.prototype
      ? lookupNodeGetter(Node.prototype, 'nodeName')
      : null;
  /* Only cache the shadowRoot getter where the engine implements Shadow DOM,
     there is no shadow root to sanitize anywhere else */
  const getShadowRoot =
    'shadowRoot' in ElementPrototype
      ? lookupNodeGetter(ElementPrototype, 'shadowRoot')
      : null;
  const removeAttributeNode = lookupGetter(
    ElementPrototype,
    'removeAttributeNode'
  );

  // As per issue #47, the web-components registry is inherited by a
  // new document created via createHTMLDocument. As per the spec
  // (http://w3c.github.io/webcomponents/spec/custom/#creating-and-passing-registries)
  // a new empty registry is used when creating a template contents owner
  // document, so we use that as our parent document to ensure nothing
  // is inherited.
  if (typeof HTMLTemplateElement === 'function') {
    const template = document.createElement('template');
    if (template.content && template.content.ownerDocument) {
      document = template.content.ownerDocument;
    }
  }

  const trustedTypesPolicy = _createTrustedTypesPolicy(
    trustedTypes,
    originalDocument
  );
  const emptyHTML = trustedTypesPolicy ? trustedTypesPolicy.createHTML('') : '';

  const {
    implementation,
    createNodeIterator,
    createDocumentFragment,
    getElementsByTagName,
  } = document;
  const { importNode } = originalDocument;

  let documentMode = {};
  try {
    documentMode = clone(document).documentMode ? document.documentMode : {};
  } catch (_) {}

  let hooks = {};

  /**
   * Expose whether this browser supports running the full DOMPurify.
   */
  DOMPurify.isSupported =
    typeof getParentNode === 'function' &&
    implementation &&
    implementation.createHTMLDocument !== undefined &&
    documentMode !== 9;

  const {
    MUSTACHE_EXPR,
    ERB_EXPR,
    TMPLIT_EXPR,
    DATA_ATTR,
    ARIA_ATTR,
    IS_SCRIPT_OR_DATA,
    ATTR_WHITESPACE,
    CUSTOM_ELEMENT,
  } = EXPRESSIONS;

  let { IS_ALLOWED_URI } = EXPRESSIONS;

  /**
   * We consider the elements and attributes below to be safe. Ideally
   * don't add any new ones but feel free to remove unwanted ones.
   */

  /* allowed element names */
  let ALLOWED_TAGS = null;
  const DEFAULT_ALLOWED_TAGS = addToSet({}, [
    ...TAGS.html,
    ...TAGS.svg,
    ...TAGS.svgFilters,
    ...TAGS.mathMl,
    ...TAGS.text,
  ]);

  /* Allowed attribute names */
  let ALLOWED_ATTR = null;
  const DEFAULT_ALLOWED_ATTR = addToSet({}, [
    ...ATTRS.html,
    ...ATTRS.svg,
    ...ATTRS.mathMl,
    ...ATTRS.xml,
  ]);

  /*
   * Configure how DOMPUrify should handle custom elements and their attributes as well as customized built-in elements.
   * @property {RegExp|Function|null} tagNameCheck one of [null, regexPattern, predicate]. Default: `null` (disallow any custom elements)
   * @property {RegExp|Function|null} attributeNameCheck one of [null, regexPattern, predicate]. Default: `null` (disallow any attributes not on the allow list)
   * @property {boolean} allowCustomizedBuiltInElements allow custom elements derived from built-ins if they pass CUSTOM_ELEMENT_HANDLING.tagNameCheck. Default: `false`.
   */
  let CUSTOM_ELEMENT_HANDLING = Object.seal(
    Object.create(null, {
      tagNameCheck: {
        writable: true,
        configurable: false,
        enumerable: true,
        value: null,
      },
      attributeNameCheck: {
        writable: true,
        configurable: false,
        enumerable: true,
        value: null,
      },
      allowCustomizedBuiltInElements: {
        writable: true,
        configurable: false,
        enumerable: true,
        value: false,
      },
    })
  );

  /* Explicitly forbidden tags (overrides ALLOWED_TAGS/ADD_TAGS) */
  let FORBID_TAGS = null;

  /* Explicitly forbidden attributes (overrides ALLOWED_ATTR/ADD_ATTR) */
  let FORBID_ATTR = null;

  /* Decide if ARIA attributes are okay */
  let ALLOW_ARIA_ATTR = true;

  /* Decide if custom data attributes are okay */
  let ALLOW_DATA_ATTR = true;

  /* Decide if unknown protocols are okay */
  let ALLOW_UNKNOWN_PROTOCOLS = false;

  /* Decide if self-closing tags in attributes are allowed.
   * Usually removed due to a mXSS issue in jQuery 3.0 */
  let ALLOW_SELF_CLOSE_IN_ATTR = true;

  /* Output should be safe for common template engines.
   * This means, DOMPurify removes data attributes, mustaches and ERB
   */
  let SAFE_FOR_TEMPLATES = false;

  /* Output should be safe even for XML used within HTML and alike.
   * This means, DOMPurify removes comments when containing risky content.
   */
  let SAFE_FOR_XML = true;

  /* Decide if document with <html>... should be returned */
  let WHOLE_DOCUMENT = false;

  /* Track whether config is already set on this instance of DOMPurify. */
  let SET_CONFIG = false;

  /* Pristine allowlist bindings captured by the last _parseConfig() run,
   * before any per-walk hook clone. sanitize() restores ALLOWED_TAGS /
   * ALLOWED_ATTR from these before the walk, so a hook's in-call widening
   * cannot carry across calls - neither on the persistent setConfig() path,
   * where _parseConfig is skipped, nor when _parseConfig returns early for
   * an already parsed config object. Reset by clearConfig(). */
  let PRISTINE_ALLOWED_TAGS = null;
  let PRISTINE_ALLOWED_ATTR = null;

  /* Decide if all elements (e.g. style, script) must be children of
   * document.body. By default, browsers might move them to document.head */
  let FORCE_BODY = false;

  /* Decide if a DOM `HTMLBodyElement` should be returned, instead of a html
   * string (or a TrustedHTML object if Trusted Types are supported).
   * If `WHOLE_DOCUMENT` is enabled a `HTMLHtmlElement` will be returned instead
   */
  let RETURN_DOM = false;

  /* Decide if a DOM `DocumentFragment` should be returned, instead of a html
   * string  (or a TrustedHTML object if Trusted Types are supported) */
  let RETURN_DOM_FRAGMENT = false;

  /* Try to return a Trusted Type object instead of a string, return a string in
   * case Trusted Types are not supported  */
  let RETURN_TRUSTED_TYPE = false;

  /* Output should be free from DOM clobbering attacks?
   * This sanitizes markups named with colliding, clobberable built-in DOM APIs.
   */
  let SANITIZE_DOM = true;

  /* Achieve full DOM Clobbering protection by isolating the namespace of named
   * properties and JS variables, mitigating attacks that abuse the HTML/DOM spec rules.
   *
   * HTML/DOM spec rules that enable DOM Clobbering:
   *   - Named Access on Window (§7.3.3)
   *   - DOM Tree Accessors (§3.1.5)
   *   - Form Element Parent-Child Relations (§4.10.3)
   *   - Iframe srcdoc / Nested WindowProxies (§4.8.5)
   *   - HTMLCollection (§4.2.10.2)
   *
   * Namespace isolation is implemented by prefixing `id` and `name` attributes
   * with a constant string, i.e., `user-content-`
   */
  let SANITIZE_NAMED_PROPS = false;
  const SANITIZE_NAMED_PROPS_PREFIX = 'user-content-';

  /* Keep element content when removing element? */
  let KEEP_CONTENT = true;

  /* If a `Node` is passed to sanitize(), then performs sanitization in-place instead
   * of importing it into a new Document and returning a sanitized copy */
  let IN_PLACE = false;

  /* Allow usage of profiles like html, svg and mathMl */
  let USE_PROFILES = {};

  /* Tags to ignore content of when KEEP_CONTENT is true */
  let FORBID_CONTENTS = null;
  const DEFAULT_FORBID_CONTENTS = addToSet({}, [
    'annotation-xml',
    'audio',
    'colgroup',
    'desc',
    'foreignobject',
    'head',
    'iframe',
    'math',
    'mi',
    'mn',
    'mo',
    'ms',
    'mtext',
    'noembed',
    'noframes',
    'noscript',
    'plaintext',
    'script',
    'style',
    'svg',
    'template',
    'thead',
    'title',
    'video',
    'xmp',
  ]);

  /* Tags that are safe for data: URIs */
  let DATA_URI_TAGS = null;
  const DEFAULT_DATA_URI_TAGS = addToSet({}, [
    'audio',
    'video',
    'img',
    'source',
    'image',
    'track',
  ]);

  /* Attributes safe for values like "javascript:" */
  let URI_SAFE_ATTRIBUTES = null;
  const DEFAULT_URI_SAFE_ATTRIBUTES = addToSet({}, [
    'alt',
    'class',
    'for',
    'id',
    'label',
    'name',
    'pattern',
    'placeholder',
    'role',
    'summary',
    'title',
    'value',
    'style',
    'xmlns',
  ]);

  const MATHML_NAMESPACE = 'http://www.w3.org/1998/Math/MathML';
  const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';
  const HTML_NAMESPACE = 'http://www.w3.org/1999/xhtml';
  /* Document namespace */
  let NAMESPACE = HTML_NAMESPACE;
  let IS_EMPTY_INPUT = false;

  /* Attached shadow roots already sanitized by the current sanitize() call */
  let SANITIZED_SHADOW_ROOTS = [];

  /* Allowed XHTML+XML namespaces */
  let ALLOWED_NAMESPACES = null;
  const DEFAULT_ALLOWED_NAMESPACES = addToSet(
    {},
    [MATHML_NAMESPACE, SVG_NAMESPACE, HTML_NAMESPACE],
    stringToString
  );

  /* Parsing of strict XHTML documents */
  let PARSER_MEDIA_TYPE;
  const SUPPORTED_PARSER_MEDIA_TYPES = ['application/xhtml+xml', 'text/html'];
  const DEFAULT_PARSER_MEDIA_TYPE = 'text/html';
  let transformCaseFunc;

  /* Keep a reference to config to pass to hooks */
  let CONFIG = null;

  /* Ideally, do not touch anything below this line */
  /* ______________________________________________ */

  const formElement = document.createElement('form');

  const isRegexOrFunction = function (testValue) {
    return testValue instanceof RegExp || testValue instanceof Function;
  };

  /**
   * _parseConfig
   *
   * @param  {Object} cfg optional config literal
   */
  // eslint-disable-next-line complexity
  const _parseConfig = function (cfg) {
    if (CONFIG && CONFIG === cfg) {
      return;
    }

    /* Shield configuration object from tampering */
    if (!cfg || typeof cfg !== 'object') {
      cfg = {};
    }

    /* Shield configuration object from prototype pollution */
    cfg = clone(cfg);

    PARSER_MEDIA_TYPE =
      // eslint-disable-next-line unicorn/prefer-includes
      SUPPORTED_PARSER_MEDIA_TYPES.indexOf(cfg.PARSER_MEDIA_TYPE) === -1
        ? (PARSER_MEDIA_TYPE = DEFAULT_PARSER_MEDIA_TYPE)
        : (PARSER_MEDIA_TYPE = cfg.PARSER_MEDIA_TYPE);

    // HTML tags and attributes are not case-sensitive, converting to lowercase. Keeping XHTML as is.
    transformCaseFunc =
      PARSER_MEDIA_TYPE === 'application/xhtml+xml'
        ? stringToString
        : stringToLowerCase;

    /* Set configuration parameters */
    ALLOWED_TAGS =
      'ALLOWED_TAGS' in cfg
        ? addToSet({}, cfg.ALLOWED_TAGS, transformCaseFunc)
        : DEFAULT_ALLOWED_TAGS;
    ALLOWED_ATTR =
      'ALLOWED_ATTR' in cfg
        ? addToSet({}, cfg.ALLOWED_ATTR, transformCaseFunc)
        : DEFAULT_ALLOWED_ATTR;
    ALLOWED_NAMESPACES =
      'ALLOWED_NAMESPACES' in cfg
        ? addToSet({}, cfg.ALLOWED_NAMESPACES, stringToString)
        : DEFAULT_ALLOWED_NAMESPACES;
    URI_SAFE_ATTRIBUTES =
      'ADD_URI_SAFE_ATTR' in cfg
        ? addToSet(
            clone(DEFAULT_URI_SAFE_ATTRIBUTES), // eslint-disable-line indent
            cfg.ADD_URI_SAFE_ATTR, // eslint-disable-line indent
            transformCaseFunc // eslint-disable-line indent
          ) // eslint-disable-line indent
        : DEFAULT_URI_SAFE_ATTRIBUTES;
    DATA_URI_TAGS =
      'ADD_DATA_URI_TAGS' in cfg
        ? addToSet(
            clone(DEFAULT_DATA_URI_TAGS), // eslint-disable-line indent
            cfg.ADD_DATA_URI_TAGS, // eslint-disable-line indent
            transformCaseFunc // eslint-disable-line indent
          ) // eslint-disable-line indent
        : DEFAULT_DATA_URI_TAGS;
    FORBID_CONTENTS =
      'FORBID_CONTENTS' in cfg
        ? addToSet({}, cfg.FORBID_CONTENTS, transformCaseFunc)
        : DEFAULT_FORBID_CONTENTS;
    FORBID_TAGS =
      'FORBID_TAGS' in cfg
        ? addToSet({}, cfg.FORBID_TAGS, transformCaseFunc)
        : {};
    FORBID_ATTR =
      'FORBID_ATTR' in cfg
        ? addToSet({}, cfg.FORBID_ATTR, transformCaseFunc)
        : {};
    USE_PROFILES = 'USE_PROFILES' in cfg ? cfg.USE_PROFILES : false;
    ALLOW_ARIA_ATTR = cfg.ALLOW_ARIA_ATTR !== false; // Default true
    ALLOW_DATA_ATTR = cfg.ALLOW_DATA_ATTR !== false; // Default true
    ALLOW_UNKNOWN_PROTOCOLS = cfg.ALLOW_UNKNOWN_PROTOCOLS || false; // Default false
    ALLOW_SELF_CLOSE_IN_ATTR = cfg.ALLOW_SELF_CLOSE_IN_ATTR !== false; // Default true
    SAFE_FOR_TEMPLATES = cfg.SAFE_FOR_TEMPLATES || false; // Default false
    SAFE_FOR_XML = cfg.SAFE_FOR_XML !== false; // Default true
    WHOLE_DOCUMENT = cfg.WHOLE_DOCUMENT || false; // Default false
    RETURN_DOM = cfg.RETURN_DOM || false; // Default false
    RETURN_DOM_FRAGMENT = cfg.RETURN_DOM_FRAGMENT || false; // Default false
    RETURN_TRUSTED_TYPE = cfg.RETURN_TRUSTED_TYPE || false; // Default false
    FORCE_BODY = cfg.FORCE_BODY || false; // Default false
    SANITIZE_DOM = cfg.SANITIZE_DOM !== false; // Default true
    SANITIZE_NAMED_PROPS = cfg.SANITIZE_NAMED_PROPS || false; // Default false
    KEEP_CONTENT = cfg.KEEP_CONTENT !== false; // Default true
    IN_PLACE = cfg.IN_PLACE || false; // Default false
    IS_ALLOWED_URI = cfg.ALLOWED_URI_REGEXP || IS_ALLOWED_URI;
    NAMESPACE = cfg.NAMESPACE || HTML_NAMESPACE;
    CUSTOM_ELEMENT_HANDLING = cfg.CUSTOM_ELEMENT_HANDLING || {};
    if (
      cfg.CUSTOM_ELEMENT_HANDLING &&
      isRegexOrFunction(cfg.CUSTOM_ELEMENT_HANDLING.tagNameCheck)
    ) {
      CUSTOM_ELEMENT_HANDLING.tagNameCheck =
        cfg.CUSTOM_ELEMENT_HANDLING.tagNameCheck;
    }

    if (
      cfg.CUSTOM_ELEMENT_HANDLING &&
      isRegexOrFunction(cfg.CUSTOM_ELEMENT_HANDLING.attributeNameCheck)
    ) {
      CUSTOM_ELEMENT_HANDLING.attributeNameCheck =
        cfg.CUSTOM_ELEMENT_HANDLING.attributeNameCheck;
    }

    if (
      cfg.CUSTOM_ELEMENT_HANDLING &&
      typeof cfg.CUSTOM_ELEMENT_HANDLING.allowCustomizedBuiltInElements ===
        'boolean'
    ) {
      CUSTOM_ELEMENT_HANDLING.allowCustomizedBuiltInElements =
        cfg.CUSTOM_ELEMENT_HANDLING.allowCustomizedBuiltInElements;
    }

    if (SAFE_FOR_TEMPLATES) {
      ALLOW_DATA_ATTR = false;
    }

    if (RETURN_DOM_FRAGMENT) {
      RETURN_DOM = true;
    }

    /* Parse profile info */
    if (USE_PROFILES) {
      ALLOWED_TAGS = addToSet({}, [...TAGS.text]);
      ALLOWED_ATTR = create(null);
      if (USE_PROFILES.html === true) {
        addToSet(ALLOWED_TAGS, TAGS.html);
        addToSet(ALLOWED_ATTR, ATTRS.html);
      }

      if (USE_PROFILES.svg === true) {
        addToSet(ALLOWED_TAGS, TAGS.svg);
        addToSet(ALLOWED_ATTR, ATTRS.svg);
        addToSet(ALLOWED_ATTR, ATTRS.xml);
      }

      if (USE_PROFILES.svgFilters === true) {
        addToSet(ALLOWED_TAGS, TAGS.svgFilters);
        addToSet(ALLOWED_ATTR, ATTRS.svg);
        addToSet(ALLOWED_ATTR, ATTRS.xml);
      }

      if (USE_PROFILES.mathMl === true) {
        addToSet(ALLOWED_TAGS, TAGS.mathMl);
        addToSet(ALLOWED_ATTR, ATTRS.mathMl);
        addToSet(ALLOWED_ATTR, ATTRS.xml);
      }
    }

    /* Merge configuration parameters */
    if (cfg.ADD_TAGS) {
      if (ALLOWED_TAGS === DEFAULT_ALLOWED_TAGS) {
        ALLOWED_TAGS = clone(ALLOWED_TAGS);
      }

      addToSet(ALLOWED_TAGS, cfg.ADD_TAGS, transformCaseFunc);
    }

    if (cfg.ADD_ATTR) {
      if (ALLOWED_ATTR === DEFAULT_ALLOWED_ATTR) {
        ALLOWED_ATTR = clone(ALLOWED_ATTR);
      }

      addToSet(ALLOWED_ATTR, cfg.ADD_ATTR, transformCaseFunc);
    }

    if (cfg.ADD_URI_SAFE_ATTR) {
      addToSet(URI_SAFE_ATTRIBUTES, cfg.ADD_URI_SAFE_ATTR, transformCaseFunc);
    }

    if (cfg.FORBID_CONTENTS) {
      if (FORBID_CONTENTS === DEFAULT_FORBID_CONTENTS) {
        FORBID_CONTENTS = clone(FORBID_CONTENTS);
      }

      addToSet(FORBID_CONTENTS, cfg.FORBID_CONTENTS, transformCaseFunc);
    }

    /* Add #text in case KEEP_CONTENT is set to true */
    if (KEEP_CONTENT) {
      ALLOWED_TAGS['#text'] = true;
    }

    /* Add html, head and body to ALLOWED_TAGS in case WHOLE_DOCUMENT is true */
    if (WHOLE_DOCUMENT) {
      addToSet(ALLOWED_TAGS, ['html', 'head', 'body']);
    }

    /* Add tbody to ALLOWED_TAGS in case tables are permitted, see #286, #365 */
    if (ALLOWED_TAGS.table) {
      addToSet(ALLOWED_TAGS, ['tbody']);
      delete FORBID_TAGS.tbody;
    }

    /* Remember the allowlists this config resolved to. They may be the
     * module-level DEFAULT_ALLOWED_TAGS / DEFAULT_ALLOWED_ATTR, which must
     * never be handed to an uponSanitize* hook by reference (see sanitize). */
    PRISTINE_ALLOWED_TAGS = ALLOWED_TAGS;
    PRISTINE_ALLOWED_ATTR = ALLOWED_ATTR;

    // Prevent further manipulation of configuration.
    // Not available in IE8, Safari 5, etc.
    if (freeze) {
      freeze(cfg);
    }

    CONFIG = cfg;
  };

  const MATHML_TEXT_INTEGRATION_POINTS = addToSet({}, [
    'mi',
    'mo',
    'mn',
    'ms',
    'mtext',
  ]);

  const HTML_INTEGRATION_POINTS = addToSet({}, ['annotation-xml']);

  // Certain elements are allowed in both SVG and HTML
  // namespace. We need to specify them explicitly
  // so that they don't get erroneously deleted from
  // HTML namespace.
  const COMMON_SVG_AND_HTML_ELEMENTS = addToSet({}, [
    'title',
    'style',
    'font',
    'a',
    'script',
  ]);

  /* Keep track of all possible SVG and MathML tags
   * so that we can perform the namespace checks
   * correctly. */
  const ALL_SVG_TAGS = addToSet({}, TAGS.svg);
  addToSet(ALL_SVG_TAGS, TAGS.svgFilters);
  addToSet(ALL_SVG_TAGS, TAGS.svgDisallowed);

  const ALL_MATHML_TAGS = addToSet({}, TAGS.mathMl);
  addToSet(ALL_MATHML_TAGS, TAGS.mathMlDisallowed);

  /**
   *
   *
   * @param  {Element} element a DOM element whose namespace is being checked
   * @returns {boolean} Return false if the element has a
   *  namespace that a spec-compliant parser would never
   *  return. Return true otherwise.
   */
  const _checkValidNamespace = function (element) {
    let parent = getParentNode(element);

    // In JSDOM, if we're inside shadow DOM, then parentNode
    // can be null. We just simulate parent in this case.
    if (!parent || !parent.tagName) {
      parent = {
        namespaceURI: NAMESPACE,
        tagName: 'template',
      };
    }

    const tagName = stringToLowerCase(element.tagName);
    const parentTagName = stringToLowerCase(parent.tagName);

    if (!ALLOWED_NAMESPACES[element.namespaceURI]) {
      return false;
    }

    if (element.namespaceURI === SVG_NAMESPACE) {
      // The only way to switch from HTML namespace to SVG
      // is via <svg>. If it happens via any other tag, then
      // it should be killed.
      if (parent.namespaceURI === HTML_NAMESPACE) {
        return tagName === 'svg';
      }

      // The only way to switch from MathML to SVG is via`
      // svg if parent is either <annotation-xml> or MathML
      // text integration points.
      if (parent.namespaceURI === MATHML_NAMESPACE) {
        return (
          tagName === 'svg' &&
          (parentTagName === 'annotation-xml' ||
            MATHML_TEXT_INTEGRATION_POINTS[parentTagName])
        );
      }

      // We only allow elements that are defined in SVG
      // spec. All others are disallowed in SVG namespace.
      return Boolean(ALL_SVG_TAGS[tagName]);
    }

    if (element.namespaceURI === MATHML_NAMESPACE) {
      // The only way to switch from HTML namespace to MathML
      // is via <math>. If it happens via any other tag, then
      // it should be killed.
      if (parent.namespaceURI === HTML_NAMESPACE) {
        return tagName === 'math';
      }

      // The only way to switch from SVG to MathML is via
      // <math> and HTML integration points
      if (parent.namespaceURI === SVG_NAMESPACE) {
        return tagName === 'math' && HTML_INTEGRATION_POINTS[parentTagName];
      }

      // We only allow elements that are defined in MathML
      // spec. All others are disallowed in MathML namespace.
      return Boolean(ALL_MATHML_TAGS[tagName]);
    }

    if (element.namespaceURI === HTML_NAMESPACE) {
      // The only way to switch from SVG to HTML is via
      // HTML integration points, and from MathML to HTML
      // is via MathML text integration points
      if (
        parent.namespaceURI === SVG_NAMESPACE &&
        !HTML_INTEGRATION_POINTS[parentTagName]
      ) {
        return false;
      }

      if (
        parent.namespaceURI === MATHML_NAMESPACE &&
        !MATHML_TEXT_INTEGRATION_POINTS[parentTagName]
      ) {
        return false;
      }

      // We disallow tags that are specific for MathML
      // or SVG and should never appear in HTML namespace
      return (
        !ALL_MATHML_TAGS[tagName] &&
        (COMMON_SVG_AND_HTML_ELEMENTS[tagName] || !ALL_SVG_TAGS[tagName])
      );
    }

    // For XHTML and XML documents that support custom namespaces
    if (
      PARSER_MEDIA_TYPE === 'application/xhtml+xml' &&
      ALLOWED_NAMESPACES[element.namespaceURI]
    ) {
      return true;
    }

    // The code should never reach this place (this means
    // that the element somehow got namespace that is not
    // HTML, SVG, MathML or allowed via ALLOWED_NAMESPACES).
    // Return false just in case.
    return false;
  };

  /**
   * _forceRemove
   *
   * @param  {Node} node a DOM node
   */
  const _forceRemove = function (node) {
    arrayPush(DOMPurify.removed, { element: node });
    try {
      // eslint-disable-next-line unicorn/prefer-dom-node-remove
      node.parentNode.removeChild(node);
    } catch (_) {
      try {
        node.outerHTML = emptyHTML;
      } catch (_) {
        node.remove();
      }
    }
  };

  /**
   * _removeAttribute
   *
   * @param  {String} name an Attribute name
   * @param  {Node} node a DOM node
   */
  const _removeAttribute = function (name, node) {
    try {
      arrayPush(DOMPurify.removed, {
        attribute: node.getAttributeNode(name),
        from: node,
      });
    } catch (_) {
      arrayPush(DOMPurify.removed, {
        attribute: null,
        from: node,
      });
    }

    node.removeAttribute(name);

    // We void attribute values for unremovable "is"" attributes
    if (name === 'is' && !ALLOWED_ATTR[name]) {
      if (RETURN_DOM || RETURN_DOM_FRAGMENT) {
        try {
          _forceRemove(node);
        } catch (_) {}
      } else {
        try {
          node.setAttribute(name, '');
        } catch (_) {}
      }
    }
  };

  /**
   * _initDocument
   *
   * @param  {String} dirty a string of dirty markup
   * @return {Document} a DOM, filled with the dirty markup
   */
  const _initDocument = function (dirty) {
    /* Create a HTML document */
    let doc;
    let leadingWhitespace;

    if (FORCE_BODY) {
      dirty = '<remove></remove>' + dirty;
    } else {
      /* If FORCE_BODY isn't used, leading whitespace needs to be preserved manually */
      const matches = stringMatch(dirty, /^[\r\n\t ]+/);
      leadingWhitespace = matches && matches[0];
    }

    if (
      PARSER_MEDIA_TYPE === 'application/xhtml+xml' &&
      NAMESPACE === HTML_NAMESPACE
    ) {
      // Root of XHTML doc must contain xmlns declaration (see https://www.w3.org/TR/xhtml1/normative.html#strict)
      dirty =
        '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>' +
        dirty +
        '</body></html>';
    }

    const dirtyPayload = trustedTypesPolicy
      ? trustedTypesPolicy.createHTML(dirty)
      : dirty;
    /*
     * Use the DOMParser API by default, fallback later if needs be
     * DOMParser not work for svg when has multiple root element.
     */
    if (NAMESPACE === HTML_NAMESPACE) {
      try {
        doc = new DOMParser().parseFromString(dirtyPayload, PARSER_MEDIA_TYPE);
      } catch (_) {}
    }

    /* Use createHTMLDocument in case DOMParser is not available */
    if (!doc || !doc.documentElement) {
      doc = implementation.createDocument(NAMESPACE, 'template', null);
      try {
        doc.documentElement.innerHTML = IS_EMPTY_INPUT
          ? emptyHTML
          : dirtyPayload;
      } catch (_) {
        // Syntax error if dirtyPayload is invalid xml
      }
    }

    const body = doc.body || doc.documentElement;

    if (dirty && leadingWhitespace) {
      body.insertBefore(
        document.createTextNode(leadingWhitespace),
        body.childNodes[0] || null
      );
    }

    /* Work on whole document or just its body */
    if (NAMESPACE === HTML_NAMESPACE) {
      return getElementsByTagName.call(
        doc,
        WHOLE_DOCUMENT ? 'html' : 'body'
      )[0];
    }

    return WHOLE_DOCUMENT ? doc.documentElement : body;
  };

  /**
   * _createIterator
   *
   * @param  {Document} root document/fragment to create iterator for
   * @return {Iterator} iterator instance
   */
  const _createIterator = function (root) {
    return createNodeIterator.call(
      root.ownerDocument || root,
      root,
      // eslint-disable-next-line no-bitwise
      NodeFilter.SHOW_ELEMENT |
        NodeFilter.SHOW_COMMENT |
        NodeFilter.SHOW_TEXT |
        NodeFilter.SHOW_PROCESSING_INSTRUCTION |
        NodeFilter.SHOW_CDATA_SECTION,
      null,
      false
    );
  };

  /**
   * _scrubTemplateExpressions
   * Strip template-engine expressions ({{...}}, <%...%>, ${...}) from the
   * character data of a subtree. Used as the final safety net for
   * SAFE_FOR_TEMPLATES on every DOM-returning code path so that expressions
   * which only form after text-node normalization (e.g. fragments split across
   * stripped elements) cannot survive into a template-evaluating framework.
   *
   * Walks text/comment/CDATA/processing-instruction nodes and rewrites their
   * `.data` in place instead of round-tripping through innerHTML. Writing
   * serialized markup back reparses it: the text of a DOM-built rawtext
   * element (e.g. a <style> holding `</style><img onerror=...>`) would come
   * back as live, never-sanitized elements, and every descendant the caller
   * holds a reference to would be replaced. NodeIterator does not enter
   * <template>.content, so each template's content is scrubbed explicitly,
   * unless ownDataOnly is set: _sanitizeShadowDOM scrubs each fragment it
   * walks, nested template contents included, so recursing there would
   * rescrub every nested fragment once per ancestor.
   *
   * @param  {Node} node The root node whose character data should be scrubbed
   * @param  {Boolean} ownDataOnly Do not recurse into <template>.content
   */
  const _scrubTemplateExpressions = function (node, ownDataOnly) {
    node.normalize();
    const walker = _createIterator(node);

    let currentNode;
    while ((currentNode = walker.nextNode())) {
      if (currentNode.nodeType === 1) {
        const { content } = currentNode;
        if (!ownDataOnly && content && content.nodeType === 11) {
          _scrubTemplateExpressions(content);
        }

        continue;
      }

      let { data } = currentNode;
      data = stringReplace(data, MUSTACHE_EXPR, ' ');
      data = stringReplace(data, ERB_EXPR, ' ');
      data = stringReplace(data, TMPLIT_EXPR, ' ');
      if (currentNode.data !== data) {
        currentNode.data = data;
      }
    }
  };

  /**
   * _getNodeType
   *
   * Realm safety (GHSA-hpcv-96wg-7vj8): read nodeType through the cached
   * Node.prototype getter instead of relying on `instanceof` checks against
   * this window's constructors. A node minted in another realm (e.g. a
   * same-origin iframe document) is an instance of the foreign realm's
   * constructors, so `instanceof` short-circuits to false for it, while the
   * getter reads the node's internal slot and works for nodes of any realm.
   * It also can not be shadowed by a clobbering form descendant.
   *
   * @param  {Node} value object to read the node type of
   * @return {Number|null} the node type, or null if value is not a DOM node
   */
  const _getNodeType = function (value) {
    if (!getNodeType || typeof value !== 'object' || value === null) {
      return null;
    }

    try {
      const nodeType = getNodeType(value);
      return typeof nodeType === 'number' ? nodeType : null;
    } catch (_) {
      return null;
    }
  };

  /**
   * _getNodeName
   *
   * Realm safety (GHSA-hpcv-96wg-7vj8): read nodeName through the cached
   * Node.prototype getter, which works for nodes of any realm and can not be
   * shadowed by a clobbering form descendant (e.g. <input name="nodeName">).
   *
   * @param  {Node} value object to read the node name of
   * @return {String|null} the node name, or null if it can not be read
   */
  const _getNodeName = function (value) {
    if (!getNodeName || typeof value !== 'object' || value === null) {
      return null;
    }

    try {
      const nodeName = getNodeName(value);
      return typeof nodeName === 'string' ? nodeName : null;
    } catch (_) {
      return null;
    }
  };

  /**
   * _isDocumentFragment
   *
   * Realm safety (GHSA-hpcv-96wg-7vj8): `value instanceof DocumentFragment`
   * is realm-bound, a fragment from a foreign realm (e.g. the content of a
   * <template> created in an iframe document) failed the check and its
   * contents were never walked. Compare the realm-independent nodeType
   * against DOCUMENT_FRAGMENT_NODE (11) instead.
   *
   * @param  {*} value object to check
   * @return {Boolean} true if value is a DocumentFragment from any realm
   */
  const _isDocumentFragment = function (value) {
    return _getNodeType(value) === 11;
  };

  /**
   * _isClobbered
   *
   * Realm safety (GHSA-hpcv-96wg-7vj8): every check in here has to work for
   * forms of a foreign realm too. `elm instanceof HTMLFormElement` and
   * `elm.attributes instanceof NamedNodeMap` are realm-bound: a form created
   * in a same-origin iframe failed the first check, so it was never treated
   * as clobbered and its attribute walk read a clobbered .attributes.
   * The form is detected by its nodeName, read through the cached
   * Node.prototype getter, and the NamedNodeMap check compares the direct
   * .attributes read against the cached Element.prototype getter. A
   * clobbering child (e.g. <input name="attributes">) makes the two reads
   * diverge, while a clean form of any realm returns its canonical
   * NamedNodeMap for both.
   *
   * @param  {Node} elm element to check for clobbering attacks
   * @return {Boolean} true if clobbered, false if safe
   */
  const _isClobbered = function (elm) {
    /* Only a form element can be clobbered. A type or name that can not be
       read through the getters means a clobbered property on engines
       without the prototype getters, or no DOM node at all: run the checks
       below instead of trusting it. */
    const realNodeType = _getNodeType(elm);
    const realNodeName = _getNodeName(elm);

    /* NodeName spoofing probe (GHSA-x4vx-rjvf-j5p4). Not only a form: any
       live node handed in with IN_PLACE can define an own nodeName (e.g. a
       <script> claiming to be a "DIV"), which diverges from the cached
       Node.prototype getter. Such a node is hostile, treat it like any other
       clobbered node. */
    if (realNodeName !== null && elm.nodeName !== realNodeName) {
      return true;
    }

    if (
      (realNodeType !== null && realNodeType !== 1) ||
      (realNodeName !== null && stringToLowerCase(realNodeName) !== 'form')
    ) {
      return false;
    }

    return (
      typeof elm.nodeName !== 'string' ||
      typeof elm.textContent !== 'string' ||
      typeof elm.removeChild !== 'function' ||
      elm.attributes !== getAttributes(elm) ||
      /* Engine-independent fallbacks for the getter probes, which can not
         tell a clobbered form apart where the engine has no prototype getter
         (see lookupNodeGetter): a real attribute map has getNamedItem and a
         real node has a numeric nodeType, a clobbering element has neither. */
      !elm.attributes ||
      typeof elm.attributes.getNamedItem !== 'function' ||
      typeof elm.nodeType !== 'number' ||
      /* NodeType clobbering probe: the cached Node.prototype.nodeType getter
         returns 1 for any element of any realm, while a direct read on a
         clobbered form (e.g. <input name="nodeType">) returns the named
         child. Several mXSS / PI / comment branches in _sanitizeElements
         compare currentNode.nodeType directly. */
      (realNodeType !== null && elm.nodeType !== realNodeType) ||
      typeof elm.removeAttribute !== 'function' ||
      typeof elm.setAttribute !== 'function' ||
      typeof elm.namespaceURI !== 'string' ||
      typeof elm.insertBefore !== 'function' ||
      typeof elm.hasChildNodes !== 'function' ||
      /* HTMLFormElement has [LegacyOverrideBuiltIns]: a descendant named
         "childNodes" shadows the prototype getter. Compare the direct read
         to the cached Node.prototype getter, the two values differ when the
         form's named-property getter intercepts the read. This catches every
         clobbering child type (input, select, etc.) */
      elm.childNodes !== getChildNodes(elm)
    );
  };

  /**
   * _isNode
   *
   * @param  {Node} obj object to check whether it's a DOM node
   * @return {Boolean} true is object is a DOM node
   */
  const _isNode = function (object) {
    /* Trust the prototype chain first. A form can clobber nodeType and
       nodeName through named descendants, which fails the duck-typing below
       and would stringify an IN_PLACE root instead of sanitizing the node,
       leaving it untouched. GHSA-r47g-fvhr-h676. */
    if (typeof Node === 'function' && object instanceof Node) {
      return true;
    }

    /* The prototype chain check is realm-bound, a node of a foreign realm
       (e.g. a same-origin iframe document) fails it. Read nodeType through
       the cached Node.prototype getter, which works across realms and can
       not be clobbered by a form's named descendants. GHSA-hpcv-96wg-7vj8,
       GHSA-4w3q-35jp-p934. */
    if (_getNodeType(object) !== null) {
      return true;
    }

    return typeof Node === 'object'
      ? object instanceof Node
      : object &&
          typeof object === 'object' &&
          typeof object.nodeType === 'number' &&
          typeof object.nodeName === 'string';
  };

  /**
   * _executeHook
   * Execute user configurable hooks
   *
   * @param  {String} entryPoint  Name of the hook's entry point
   * @param  {Node} currentNode node to work on with the hook
   * @param  {Object} data additional hook parameters
   */
  const _executeHook = function (entryPoint, currentNode, data) {
    if (!hooks[entryPoint]) {
      return;
    }

    arrayForEach(hooks[entryPoint], (hook) => {
      hook.call(DOMPurify, currentNode, data, CONFIG);
    });
  };

  /**
   * _hasHooks
   * Whether at least one hook is registered for an entry point, read the
   * same way _executeHook reads it
   *
   * @param  {String} entryPoint  Name of the hook's entry point
   * @return {Boolean} true if _executeHook would run a hook
   */
  const _hasHooks = function (entryPoint) {
    const entryHooks = hooks[entryPoint];
    return Boolean(entryHooks) && entryHooks.length > 0;
  };

  /**
   * _forkSharedAllowlist
   * Fork a hook-mutable allowlist off its shared binding right before an
   * uponSanitize* hook sees it. The per-walk clone in sanitize() samples the
   * hooks once, before the walk, so a hook installed later in the walk (e.g.
   * from beforeSanitizeElements) would otherwise get the module default or
   * the pristine config binding by reference and could widen it for good.
   * Returns the set unchanged once it is call-local, so repeated calls are
   * idempotent.
   *
   * @param  {String} entryPoint  Name of the uponSanitize* hook
   * @param  {Object} set         Current ALLOWED_TAGS / ALLOWED_ATTR binding
   * @param  {Object} defaultSet  DEFAULT_ALLOWED_TAGS / DEFAULT_ALLOWED_ATTR
   * @param  {Object} pristineSet PRISTINE_ALLOWED_TAGS / PRISTINE_ALLOWED_ATTR
   * @return {Object} a call-local clone if needed, else set
   */
  const _forkSharedAllowlist = function (
    entryPoint,
    set,
    defaultSet,
    pristineSet
  ) {
    if (!_hasHooks(entryPoint)) {
      return set;
    }

    return set === defaultSet || set === pristineSet ? clone(set) : set;
  };

  /**
   * _stripDisallowedAttributes
   * Remove every attribute of an element that the attribute allowlist
   * rejects. Hook-free and not recorded in DOMPurify.removed: it only runs
   * on nodes that already left the tree being sanitized. All reads go
   * through the cached prototype getters so a clobbering form cannot hide
   * an attribute from the scrub.
   *
   * @param  {Element} element element to scrub
   */
  const _stripDisallowedAttributes = function (element) {
    const attributes = getAttributes(element);
    if (!attributes) {
      return;
    }

    const lcTag = transformCaseFunc(_getNodeName(element) || '');
    let l = attributes.length;
    while (l--) {
      const attr = attributes[l];
      if (!attr) {
        continue;
      }

      const { name } = attr;
      const value = name === 'value' ? attr.value : stringTrim(attr.value);
      if (!_isValidAttribute(lcTag, transformCaseFunc(name), value)) {
        try {
          removeAttributeNode(element, attr);
        } catch (_) {}
      }
    }
  };

  /**
   * _neutralizeSubtree
   * Strip the non-allow-listed attributes (on* handlers, script URIs, ...)
   * from every element of a subtree, the subtree root included. Iterative,
   * so a deeply nested subtree cannot exhaust the stack.
   *
   * @param  {Node} node root of the subtree to neutralize
   */
  const _neutralizeSubtree = function (node) {
    const stack = [node];
    while (stack.length > 0) {
      const current = arrayPop(stack);
      if (_getNodeType(current) === 1) {
        _stripDisallowedAttributes(current);
      }

      const childNodes = getChildNodes(current);
      let i = childNodes ? childNodes.length : 0;
      while (i--) {
        arrayPush(stack, childNodes[i]);
      }
    }
  };

  /**
   * _neutralizeHookDetachedNode
   * A hook may detach the node it is handed, e.g. via the documented
   * node.remove() pattern. The iterator then never visits the detached
   * subtree, and the node is not recorded in DOMPurify.removed. On the
   * IN_PLACE path the caller built that subtree in the live document, so a
   * descendant that already started loading (e.g. <img src=x onerror=...>)
   * keeps its queued handler and fires in page scope after sanitize
   * returns, even though the handler never reached the returned tree.
   * Neutralize the detached subtree before the walk moves on. The walk root
   * is exempt: a detached IN_PLACE root is legitimate input and keeps being
   * sanitized by the walk itself. CVE-2026-75838.
   *
   * @param  {Node} node the node a hook was just run on
   * @param  {Node} root the root of the current walk
   * @return {Boolean} true if the node was detached and neutralized
   */
  const _neutralizeHookDetachedNode = function (node, root) {
    if (!IN_PLACE || node === root || getParentNode(node) !== null) {
      return false;
    }

    _neutralizeSubtree(node);
    return true;
  };

  /**
   * _sanitizeElements
   *
   * @protect nodeName
   * @protect textContent
   * @protect removeChild
   *
   * @param   {Node} currentNode to check for permission to exist
   * @param   {Node} root the root of the current walk
   * @return  {Boolean} true if node was killed, false if left alive
   */
  const _sanitizeElements = function (currentNode, root) {
    let content;

    /* Execute a hook if present */
    _executeHook('beforeSanitizeElements', currentNode, null);

    /* The hook may have detached the node. On the IN_PLACE path,
       neutralize the detached subtree so a queued resource handler on it
       cannot fire in page scope after we return. */
    _neutralizeHookDetachedNode(currentNode, root);

    /* Check if element is clobbered or can clobber */
    if (_isClobbered(currentNode)) {
      _forceRemove(currentNode);
      return true;
    }

    /* Read the name through the cached getter, an own nodeName property can
       not spoof it (GHSA-x4vx-rjvf-j5p4) */
    const nodeName = _getNodeName(currentNode) || currentNode.nodeName;

    /* Check if tagname contains Unicode */
    if (regExpTest(/[\u0080-\uFFFF]/, nodeName)) {
      _forceRemove(currentNode);
      return true;
    }

    /* Now let's check the element's type and name */
    const tagName = transformCaseFunc(nodeName);

    /* Fork ALLOWED_TAGS off a shared binding before a hook installed after
       the per-walk clone can see it */
    ALLOWED_TAGS = _forkSharedAllowlist(
      'uponSanitizeElement',
      ALLOWED_TAGS,
      DEFAULT_ALLOWED_TAGS,
      PRISTINE_ALLOWED_TAGS
    );

    /* Execute a hook if present */
    _executeHook('uponSanitizeElement', currentNode, {
      tagName,
      allowedTags: ALLOWED_TAGS,
    });

    /* Same detach re-check as after beforeSanitizeElements: a hook-detached
       node is not recorded in DOMPurify.removed and the iterator never
       visits its descendants (see _neutralizeHookDetachedNode). */
    _neutralizeHookDetachedNode(currentNode, root);

    /* Detect mXSS attempts abusing namespace confusion */
    if (
      currentNode.hasChildNodes() &&
      !_isNode(currentNode.firstElementChild) &&
      (!_isNode(currentNode.content) ||
        !_isNode(currentNode.content.firstElementChild)) &&
      regExpTest(/<[/\w]/g, currentNode.innerHTML) &&
      regExpTest(/<[/\w]/g, currentNode.textContent)
    ) {
      _forceRemove(currentNode);
      return true;
    }

    /* Mitigate a problem with templates inside select */
    if (
      tagName === 'select' &&
      regExpTest(/<template/i, currentNode.innerHTML)
    ) {
      _forceRemove(currentNode);
      return true;
    }

    /* Remove any ocurrence of processing instructions */
    if (currentNode.nodeType === 7) {
      _forceRemove(currentNode);
      return true;
    }

    /* Remove any kind of possibly harmful comments */
    if (
      SAFE_FOR_XML &&
      currentNode.nodeType === 8 &&
      regExpTest(/<[/\w]/g, currentNode.data)
    ) {
      _forceRemove(currentNode);
      return true;
    }

    /* Remove element if anything forbids its presence */
    if (!ALLOWED_TAGS[tagName] || FORBID_TAGS[tagName]) {
      /* Check if we have a custom element to handle */
      if (!FORBID_TAGS[tagName] && _basicCustomElementTest(tagName)) {
        if (
          CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof RegExp &&
          regExpTest(CUSTOM_ELEMENT_HANDLING.tagNameCheck, tagName)
        )
          return false;
        if (
          CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof Function &&
          CUSTOM_ELEMENT_HANDLING.tagNameCheck(tagName)
        )
          return false;
      }

      /* Keep content except for bad-listed elements.
         Use the cached prototype getters exclusively: a direct
         `currentNode.parentNode` / `currentNode.childNodes` fallback is dead
         in safe cases and a clobbering surface in unsafe ones. Falsy cached
         results stay falsy; the `if (childNodes && parentNode)` check
         already gates correctly. */
      if (
        KEEP_CONTENT &&
        !FORBID_CONTENTS[tagName] &&
        /* Never hoist a removed IN_PLACE root's content into the caller's
           live parent: it lies outside the walk and would never be
           sanitized. The root-removed throw in sanitize() refuses the call.
           GHSA-6688-9rhm-gjv2 */
        !(IN_PLACE && currentNode === root)
      ) {
        const parentNode = getParentNode(currentNode);
        const childNodes = getChildNodes(currentNode);

        if (childNodes && parentNode) {
          const childCount = childNodes.length;

          for (let i = childCount - 1; i >= 0; --i) {
            const childClone = cloneNode(childNodes[i], true);
            childClone.__removalCount = (currentNode.__removalCount || 0) + 1;
            parentNode.insertBefore(childClone, getNextSibling(currentNode));
          }
        }
      }

      _forceRemove(currentNode);
      return true;
    }

    /* Check whether element has a valid namespace. Realm-safe check
       (GHSA-hpcv-96wg-7vj8): read nodeType through the cached getter rather
       than using `instanceof Element`, which is realm-bound and let an
       element of a foreign realm skip the namespace check entirely. */
    if (
      _getNodeType(currentNode) === 1 &&
      !_checkValidNamespace(currentNode)
    ) {
      _forceRemove(currentNode);
      return true;
    }

    /* Make sure that older browsers don't get fallback-tag mXSS */
    if (
      (tagName === 'noscript' ||
        tagName === 'noembed' ||
        tagName === 'noframes') &&
      regExpTest(/<\/no(script|embed|frames)/i, currentNode.innerHTML)
    ) {
      _forceRemove(currentNode);
      return true;
    }

    /* Sanitize element content to be template-safe */
    if (SAFE_FOR_TEMPLATES && currentNode.nodeType === 3) {
      /* Get the element's text content */
      content = currentNode.textContent;
      content = stringReplace(content, MUSTACHE_EXPR, ' ');
      content = stringReplace(content, ERB_EXPR, ' ');
      content = stringReplace(content, TMPLIT_EXPR, ' ');
      if (currentNode.textContent !== content) {
        arrayPush(DOMPurify.removed, { element: currentNode.cloneNode() });
        currentNode.textContent = content;
      }
    }

    /* Execute a hook if present */
    _executeHook('afterSanitizeElements', currentNode, null);

    /* The afterSanitizeElements hook is the documented place for
       node.remove() policies, and a detach here is invisible to every later
       pass: the iterator advances past the detached subtree, so its
       descendants are never visited. Apply the same detach-neutralization
       as the before/upon sites. */
    _neutralizeHookDetachedNode(currentNode, root);

    return false;
  };

  /**
   * _isValidAttribute
   *
   * @param  {string} lcTag Lowercase tag name of containing element.
   * @param  {string} lcName Lowercase attribute name.
   * @param  {string} value Attribute value.
   * @return {Boolean} Returns true if `value` is valid, otherwise false.
   */
  // eslint-disable-next-line complexity
  const _isValidAttribute = function (lcTag, lcName, value) {
    /* Make sure attribute cannot clobber */
    if (
      SANITIZE_DOM &&
      (lcName === 'id' || lcName === 'name') &&
      (value in document || value in formElement)
    ) {
      return false;
    }

    /* Allow valid data-* attributes: At least one character after "-"
        (https://html.spec.whatwg.org/multipage/dom.html#embedding-custom-non-visible-data-with-the-data-*-attributes)
        XML-compatible (https://html.spec.whatwg.org/multipage/infrastructure.html#xml-compatible and http://www.w3.org/TR/xml/#d0e804)
        We don't need to check the value; it's always URI safe. */
    if (
      ALLOW_DATA_ATTR &&
      !FORBID_ATTR[lcName] &&
      regExpTest(DATA_ATTR, lcName)
    ) {
      // This attribute is safe
    } else if (ALLOW_ARIA_ATTR && regExpTest(ARIA_ATTR, lcName)) {
      // This attribute is safe
      /* Otherwise, check the name is permitted */
    } else if (!ALLOWED_ATTR[lcName] || FORBID_ATTR[lcName]) {
      if (
        // First condition does a very basic check if a) it's basically a valid custom element tagname AND
        // b) if the tagName passes whatever the user has configured for CUSTOM_ELEMENT_HANDLING.tagNameCheck
        // and c) if the attribute name passes whatever the user has configured for CUSTOM_ELEMENT_HANDLING.attributeNameCheck
        (_basicCustomElementTest(lcTag) &&
          ((CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof RegExp &&
            regExpTest(CUSTOM_ELEMENT_HANDLING.tagNameCheck, lcTag)) ||
            (CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof Function &&
              CUSTOM_ELEMENT_HANDLING.tagNameCheck(lcTag))) &&
          ((CUSTOM_ELEMENT_HANDLING.attributeNameCheck instanceof RegExp &&
            regExpTest(CUSTOM_ELEMENT_HANDLING.attributeNameCheck, lcName)) ||
            (CUSTOM_ELEMENT_HANDLING.attributeNameCheck instanceof Function &&
              CUSTOM_ELEMENT_HANDLING.attributeNameCheck(lcName)))) ||
        // Alternative, second condition checks if it's an `is`-attribute, AND
        // the value passes whatever the user has configured for CUSTOM_ELEMENT_HANDLING.tagNameCheck
        (lcName === 'is' &&
          CUSTOM_ELEMENT_HANDLING.allowCustomizedBuiltInElements &&
          ((CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof RegExp &&
            regExpTest(CUSTOM_ELEMENT_HANDLING.tagNameCheck, value)) ||
            (CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof Function &&
              CUSTOM_ELEMENT_HANDLING.tagNameCheck(value))))
      ) {
        // If user has supplied a regexp or function in CUSTOM_ELEMENT_HANDLING.tagNameCheck, we need to also allow derived custom elements using the same tagName test.
        // Additionally, we need to allow attributes passing the CUSTOM_ELEMENT_HANDLING.attributeNameCheck user has configured, as custom elements can define these at their own discretion.
      } else {
        return false;
      }
      /* Check value is safe. First, is attr inert? If so, is safe */
    } else if (URI_SAFE_ATTRIBUTES[lcName]) {
      // This attribute is safe
      /* Check no script, data or unknown possibly unsafe URI
        unless we know URI values are safe for that attribute */
    } else if (
      regExpTest(IS_ALLOWED_URI, stringReplace(value, ATTR_WHITESPACE, ''))
    ) {
      // This attribute is safe
      /* Keep image data URIs alive if src/xlink:href is allowed */
      /* Further prevent gadget XSS for dynamically built script tags */
    } else if (
      (lcName === 'src' || lcName === 'xlink:href' || lcName === 'href') &&
      lcTag !== 'script' &&
      stringIndexOf(value, 'data:') === 0 &&
      DATA_URI_TAGS[lcTag]
    ) {
      // This attribute is safe
      /* Allow unknown protocols: This provides support for links that
        are handled by protocol handlers which may be unknown ahead of
        time, e.g. fb:, spotify: */
    } else if (
      ALLOW_UNKNOWN_PROTOCOLS &&
      !regExpTest(IS_SCRIPT_OR_DATA, stringReplace(value, ATTR_WHITESPACE, ''))
    ) {
      // This attribute is safe
      /* Check for binary attributes */
    } else if (value) {
      return false;
    } else {
      // Binary attributes are safe at this point
      /* Anything else, presume unsafe, do not add it back */
    }

    return true;
  };

  /**
   * _basicCustomElementCheck
   * checks if at least one dash is included in tagName, and it's not the first char
   * for more sophisticated checking see https://github.com/sindresorhus/validate-element-name
   * @param {string} tagName name of the tag of the node to sanitize
   */
  const _basicCustomElementTest = function (tagName) {
    return tagName !== 'annotation-xml' && stringMatch(tagName, CUSTOM_ELEMENT);
  };

  /**
   * _sanitizeAttributes
   *
   * @protect attributes
   * @protect nodeName
   * @protect removeAttribute
   * @protect setAttribute
   *
   * @param  {Node} currentNode to sanitize
   * @param  {Node} root the root of the current walk
   */
  const _sanitizeAttributes = function (currentNode, root) {
    let attr;
    let value;
    let lcName;
    let l;
    /* The attribute hooks can detach the node exactly like the element
       hooks can. Only a detach by the hook itself is handled here: a node
       _sanitizeElements already removed is DOMPurify's own removal, so the
       attachment is sampled before each hook runs. */
    let attachedBeforeHook = IN_PLACE && getParentNode(currentNode) !== null;

    /* Execute a hook if present */
    _executeHook('beforeSanitizeAttributes', currentNode, null);

    /* On the IN_PLACE path, neutralize a subtree the hook detached (see
       _neutralizeHookDetachedNode for the full rationale). */
    if (attachedBeforeHook) {
      _neutralizeHookDetachedNode(currentNode, root);
    }

    const { attributes } = currentNode;

    /* Check if we have attributes; if not we might have a text node */
    if (!attributes || _isClobbered(currentNode)) {
      return;
    }

    /* Same late-installed hook guard as for uponSanitizeElement */
    ALLOWED_ATTR = _forkSharedAllowlist(
      'uponSanitizeAttribute',
      ALLOWED_ATTR,
      DEFAULT_ALLOWED_ATTR,
      PRISTINE_ALLOWED_ATTR
    );

    const hookEvent = {
      attrName: '',
      attrValue: '',
      keepAttr: true,
      allowedAttributes: ALLOWED_ATTR,
    };
    l = attributes.length;

    /* Go backwards over all attributes; safely remove bad ones */
    while (l--) {
      attr = attributes[l];
      const { name, namespaceURI } = attr;
      value = name === 'value' ? attr.value : stringTrim(attr.value);
      lcName = transformCaseFunc(name);

      /* Execute a hook if present */
      hookEvent.attrName = lcName;
      hookEvent.attrValue = value;
      hookEvent.keepAttr = true;
      hookEvent.forceKeepAttr = undefined; // Allows developers to see this is a property they can set
      _executeHook('uponSanitizeAttribute', currentNode, hookEvent);
      value = hookEvent.attrValue;

      /* Did the hooks approve of the attribute? */
      if (hookEvent.forceKeepAttr) {
        continue;
      }

      /* Remove attribute */
      _removeAttribute(name, currentNode);

      /* Did the hooks approve of the attribute? */
      if (!hookEvent.keepAttr) {
        continue;
      }

      /* Work around a security issue in jQuery 3.0 */
      if (!ALLOW_SELF_CLOSE_IN_ATTR && regExpTest(/\/>/i, value)) {
        _removeAttribute(name, currentNode);
        continue;
      }

      /* Sanitize attribute content to be template-safe */
      if (SAFE_FOR_TEMPLATES) {
        value = stringReplace(value, MUSTACHE_EXPR, ' ');
        value = stringReplace(value, ERB_EXPR, ' ');
        value = stringReplace(value, TMPLIT_EXPR, ' ');
      }

      /* Is `value` valid for this attribute? The tag name is read through
         the cached getter, so a spoofed nodeName (e.g. an <a> claiming to
         be an "IMG") can not unlock data: URIs (GHSA-x4vx-rjvf-j5p4) */
      const lcTag = transformCaseFunc(
        _getNodeName(currentNode) || currentNode.nodeName
      );
      if (!_isValidAttribute(lcTag, lcName, value)) {
        continue;
      }

      /* Full DOM Clobbering protection via namespace isolation,
       * Prefix id and name attributes with `user-content-`
       */
      if (SANITIZE_NAMED_PROPS && (lcName === 'id' || lcName === 'name')) {
        // Remove the attribute with this value
        _removeAttribute(name, currentNode);

        // Prefix the value and later re-create the attribute with the sanitized value
        value = SANITIZE_NAMED_PROPS_PREFIX + value;
      }

      /* Work around a security issue with comments inside attributes */
      if (
        SAFE_FOR_XML &&
        regExpTest(
          /((--!?|])>)|<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i,
          value
        )
      ) {
        _removeAttribute(name, currentNode);
        continue;
      }

      /* Handle attributes that require Trusted Types */
      if (
        trustedTypesPolicy &&
        typeof trustedTypes === 'object' &&
        typeof trustedTypes.getAttributeType === 'function'
      ) {
        if (namespaceURI) {
          /* Namespaces are not yet supported, see https://bugs.chromium.org/p/chromium/issues/detail?id=1305293 */
        } else {
          switch (trustedTypes.getAttributeType(lcTag, lcName)) {
            case 'TrustedHTML': {
              value = trustedTypesPolicy.createHTML(value);
              break;
            }

            case 'TrustedScriptURL': {
              value = trustedTypesPolicy.createScriptURL(value);
              break;
            }

            default: {
              break;
            }
          }
        }
      }

      /* Handle invalid data-* attribute set by try-catching it */
      try {
        if (namespaceURI) {
          currentNode.setAttributeNS(namespaceURI, name, value);
        } else {
          /* Fallback to setAttribute() for browser-unrecognized namespaces e.g. "x-schema". */
          currentNode.setAttribute(name, value);
        }

        if (_isClobbered(currentNode)) {
          _forceRemove(currentNode);
        } else {
          arrayPop(DOMPurify.removed);
        }
      } catch (_) {}
    }

    attachedBeforeHook = IN_PLACE && getParentNode(currentNode) !== null;

    /* Execute a hook if present */
    _executeHook('afterSanitizeAttributes', currentNode, null);

    /* Same detach re-check as after beforeSanitizeAttributes: this is the
       last hook that runs for the node, so a detach here would otherwise
       hand the caller a live, handler-bearing subtree. */
    if (attachedBeforeHook) {
      _neutralizeHookDetachedNode(currentNode, root);
    }
  };

  /**
   * _sanitizeShadowDOM
   *
   * @param  {DocumentFragment} fragment to iterate over recursively
   */
  const _sanitizeShadowDOM = function (fragment) {
    let shadowNode;
    const shadowIterator = _createIterator(fragment);

    /* Execute a hook if present */
    _executeHook('beforeSanitizeShadowDOM', fragment, null);

    while ((shadowNode = shadowIterator.nextNode())) {
      /* Execute a hook if present */
      _executeHook('uponSanitizeShadowNode', shadowNode, null);
      /* Sanitize tags and elements */
      _sanitizeElements(shadowNode, fragment);

      /* Check attributes next */
      _sanitizeAttributes(shadowNode, fragment);

      /* Deep shadow DOM detected. Realm-safe check (GHSA-hpcv-96wg-7vj8):
         nodeType-based detection instead of instanceof, so <template>.content
         of a foreign realm is walked too. */
      if (_isDocumentFragment(shadowNode.content)) {
        _sanitizeShadowDOM(shadowNode.content);
      }

      /* An element iterated here may itself host an attached shadow root.
         The NodeIterator does not enter shadow trees, so a shadow root
         nested inside <template>.content was reached by no walk at all (the
         template-content recursion above iterates the content but never
         inspected shadowRoot), and its payload survived. Walk it explicitly.
         The shadowRoot is read through the cached Element.prototype getter,
         and only for element nodes, as the iterator also surfaces text and
         comment nodes. CVE-2026-49978. */
      if (getShadowRoot && _getNodeType(shadowNode) === 1) {
        const innerShadowRoot = getShadowRoot(shadowNode);
        if (_isDocumentFragment(innerShadowRoot)) {
          _sanitizeShadowRoot(innerShadowRoot);
        }
      }
    }

    /* The per-node strip in _sanitizeElements sees each text node alone, so
       an expression split across text nodes by a removed element survives
       inside template content: NodeIterator does not enter it and
       normalize() on the light DOM does not merge across that boundary.
       Merge and re-scrub this fragment before the hook sees it. */
    if (SAFE_FOR_TEMPLATES) {
      _scrubTemplateExpressions(fragment, true);
    }

    /* Execute a hook if present */
    _executeHook('afterSanitizeShadowDOM', fragment, null);
  };

  /**
   * _sanitizeAttachedShadowRoots
   *
   * Walks `root` and feeds every attached shadow root it finds into
   * _sanitizeShadowDOM. The node iterator does not descend into shadow
   * trees, so an open shadow root attached to the IN_PLACE root or to any
   * element below it (or deep-cloned by importNode() for a clonable shadow
   * root) would otherwise never be sanitized. Runs before the main walk.
   * Children are snapshotted first, as a hook may detach siblings.
   * All reads go through the cached prototype getters, so a clobbering form
   * descendant can not steer the walk. Upstream b4fdfe2e, e4790120.
   * CVE-2026-49978.
   *
   * @param  {Node} root the subtree root to walk for attached shadow roots
   */
  const _sanitizeAttachedShadowRoots = function (root) {
    if (!getShadowRoot) {
      return;
    }

    const nodeType = _getNodeType(root);
    if (nodeType === 1) {
      const shadowRoot = getShadowRoot(root);
      if (_isDocumentFragment(shadowRoot)) {
        _sanitizeShadowRoot(shadowRoot);
      }
    } else if (nodeType !== 9 && nodeType !== 11) {
      return;
    }

    const childNodes = getChildNodes(root);
    if (!childNodes) {
      return;
    }

    const snapshot = [];
    arrayForEach(childNodes, (child) => {
      arrayPush(snapshot, child);
    });
    arrayForEach(snapshot, (child) => {
      _sanitizeAttachedShadowRoots(child);
    });

    /* A <template> keeps its children in .content */
    if (nodeType === 1 && _isDocumentFragment(root.content)) {
      _sanitizeAttachedShadowRoots(root.content);
    }
  };

  /**
   * _sanitizeShadowRoot
   *
   * Sanitizes an attached shadow root. Nested shadow roots are walked first,
   * so that they are reached even if _sanitizeShadowDOM removes their hosts,
   * then the shadow root itself is sanitized. That walk and the shadowRoot
   * check in _sanitizeShadowDOM both reach every nested shadow root, so each
   * one is handled once per sanitize() call. A shadow root nested n levels
   * deep would otherwise be sanitized 2^n times. CVE-2026-49978.
   *
   * @param  {DocumentFragment} shadowRoot the attached shadow root
   */
  const _sanitizeShadowRoot = function (shadowRoot) {
    if (arrayIndexOf(SANITIZED_SHADOW_ROOTS, shadowRoot) !== -1) {
      return;
    }

    arrayPush(SANITIZED_SHADOW_ROOTS, shadowRoot);
    _sanitizeAttachedShadowRoots(shadowRoot);
    _sanitizeShadowDOM(shadowRoot);
  };

  /**
   * Sanitize
   * Public method providing core sanitation functionality
   *
   * @param {String|Node} dirty string or DOM node
   * @param {Object} configuration object
   */
  // eslint-disable-next-line complexity
  DOMPurify.sanitize = function (dirty, cfg = {}) {
    let body;
    let importedNode;
    let currentNode;
    let oldNode;
    let returnNode;
    /* Make sure we have a string to sanitize.
      DO NOT return early, as this will return the wrong type if
      the user has requested a DOM object rather than a string */
    IS_EMPTY_INPUT = !dirty;
    if (IS_EMPTY_INPUT) {
      dirty = '<!-->';
    }

    /* Stringify, in case dirty is an object */
    if (typeof dirty !== 'string' && !_isNode(dirty)) {
      if (typeof dirty.toString === 'function') {
        dirty = dirty.toString();
        if (typeof dirty !== 'string') {
          throw typeErrorCreate('dirty is not a string, aborting');
        }
      } else {
        throw typeErrorCreate('toString is not a function');
      }
    }

    /* Check we can run. Otherwise fall back or ignore */
    if (!DOMPurify.isSupported) {
      if (
        typeof window.toStaticHTML === 'object' ||
        typeof window.toStaticHTML === 'function'
      ) {
        if (typeof dirty === 'string') {
          return window.toStaticHTML(dirty);
        }

        if (_isNode(dirty)) {
          return window.toStaticHTML(dirty.outerHTML);
        }
      }

      return dirty;
    }

    /* Assign config vars */
    if (!SET_CONFIG) {
      _parseConfig(cfg);
    }

    /* Restore the allowlists from the pristine bindings of the active config.
     * On the persistent setConfig() path _parseConfig is skipped, and it
     * returns early for an already parsed config object, so without this a
     * previous call's hook clone (mutated below) would carry over. */
    ALLOWED_TAGS = PRISTINE_ALLOWED_TAGS;
    ALLOWED_ATTR = PRISTINE_ALLOWED_ATTR;

    /* The uponSanitizeElement hook event exposes ALLOWED_TAGS (as
     * allowedTags) and the uponSanitizeAttribute hook event exposes
     * ALLOWED_ATTR (as allowedAttributes) by reference. Without an explicit
     * ALLOWED_TAGS / ALLOWED_ATTR those are the module-level defaults, so a
     * hook that widens them would mutate the shared sets permanently, across
     * later calls and even after removeAllHooks() / clearConfig(). Clone them
     * per walk whenever such a hook is registered, so documented in-call
     * widening only mutates this call's copy. */
    if (_hasHooks('uponSanitizeElement')) {
      ALLOWED_TAGS = clone(ALLOWED_TAGS);
    }

    if (_hasHooks('uponSanitizeAttribute')) {
      ALLOWED_ATTR = clone(ALLOWED_ATTR);
    }

    /* Clean up removed elements */
    DOMPurify.removed = [];

    /* Clean up the shadow roots sanitized by a previous call */
    SANITIZED_SHADOW_ROOTS = [];

    /* Check if dirty is correctly typed for IN_PLACE */
    if (typeof dirty === 'string') {
      IN_PLACE = false;
    }

    if (IN_PLACE) {
      /* Do some early pre-sanitization to avoid unsafe root nodes.
         Read nodeName through the cached prototype getter: a clobbering
         child named "nodeName" on a form root would otherwise shadow it. */
      const rootNodeName = _getNodeName(dirty) || dirty.nodeName;
      if (rootNodeName) {
        const tagName = transformCaseFunc(rootNodeName);
        if (!ALLOWED_TAGS[tagName] || FORBID_TAGS[tagName]) {
          throw typeErrorCreate(
            'root node is forbidden and cannot be sanitized in-place'
          );
        }
      }

      /* Pre-flight the root through _isClobbered. The iterator-driven
         removal path can not detach a parent-less root: _forceRemove
         falls back to setting outerHTML and to remove(), both of which are
         no-ops on a node with no parent. A clobbered root would then
         survive the main loop with its attributes uninspected, because
         _sanitizeAttributes returns early for clobbered nodes. The result
         would be an attacker-controlled element, complete with any
         event-handler attributes the caller passed in, handed back to the
         application unsanitized. Refuse to sanitize such a root.
         GHSA-r47g-fvhr-h676. _isClobbered detects the form through the
         cached getters rather than `instanceof HTMLFormElement`, which is
         realm-bound and let a clobbered root of a foreign realm skip this
         pre-flight. GHSA-hpcv-96wg-7vj8. */
      if (_isClobbered(dirty)) {
        throw typeErrorCreate(
          'root node is clobbered and cannot be sanitized in-place'
        );
      }

      /* Sanitize attached shadow roots before the main iterator runs.
         The iterator does not descend into shadow trees. CVE-2026-49978 */
      _sanitizeAttachedShadowRoots(dirty);
    } else if (dirty instanceof Node) {
      /* If dirty is a DOM element, append to an empty document to avoid
         elements being stripped by the parser */
      body = _initDocument('<!---->');
      importedNode = body.ownerDocument.importNode(dirty, true);
      if (importedNode.nodeType === 1 && importedNode.nodeName === 'BODY') {
        /* Node is already a body, use as is */
        body = importedNode;
      } else if (importedNode.nodeName === 'HTML') {
        body = importedNode;
      } else {
        // eslint-disable-next-line unicorn/prefer-dom-node-append
        body.appendChild(importedNode);
      }

      /* Clonable shadow roots are deep-cloned by importNode(); sanitize
         them before the main iterator runs, since the iterator does not
         descend into shadow trees. Walk from `body`: an imported fragment
         was emptied into it by the appendChild() above. CVE-2026-49978 */
      _sanitizeAttachedShadowRoots(body);
    } else {
      /* Exit directly if we have nothing to do */
      if (
        !RETURN_DOM &&
        !SAFE_FOR_TEMPLATES &&
        !WHOLE_DOCUMENT &&
        // eslint-disable-next-line unicorn/prefer-includes
        dirty.indexOf('<') === -1
      ) {
        return trustedTypesPolicy && RETURN_TRUSTED_TYPE
          ? trustedTypesPolicy.createHTML(dirty)
          : dirty;
      }

      /* Initialize the document to work on */
      body = _initDocument(dirty);

      /* Check we have a DOM node from the data */
      if (!body) {
        return RETURN_DOM ? null : RETURN_TRUSTED_TYPE ? emptyHTML : '';
      }
    }

    /* Remove first element node (ours) if FORCE_BODY is set */
    if (body && FORCE_BODY) {
      _forceRemove(body.firstChild);
    }

    /* Get node iterator */
    const walkRoot = IN_PLACE ? dirty : body;
    const nodeIterator = _createIterator(walkRoot);

    /* Now start iterating over the created document */
    while ((currentNode = nodeIterator.nextNode())) {
      /* Fix IE's strange behavior with manipulated textNodes #89 */
      if (currentNode.nodeType === 3 && currentNode === oldNode) {
        continue;
      }

      /* Sanitize tags and elements */
      _sanitizeElements(currentNode, walkRoot);

      /* Check attributes next */
      _sanitizeAttributes(currentNode, walkRoot);

      /* Shadow DOM detected, sanitize it. Realm-safe check
         (GHSA-hpcv-96wg-7vj8): nodeType-based detection instead of
         instanceof, so <template>.content of a foreign realm is walked. */
      if (_isDocumentFragment(currentNode.content)) {
        _sanitizeShadowDOM(currentNode.content);
      }

      oldNode = currentNode;
    }

    oldNode = null;
    SANITIZED_SHADOW_ROOTS = [];

    /* If we sanitized `dirty` in-place, return it. */
    if (IN_PLACE) {
      /* The in-place ROOT may itself have been force-removed during the walk
         (an mXSS-canary rawtext root such as a <style> whose text carries its
         own end tag, a fallback-tag noscript/noembed/noframes root, a root a
         hook disallowed or clobbered, a root in an invalid namespace, ...).
         Such a root is detached (or, without a parent, could not be detached
         at all), and for a rawtext element its text may still carry a
         literal `</tag>`-bearing payload, so re-serialising and re-parsing
         the returned node re-opens the markup.
         There is no safe node to hand back: cancel the attribute axis on the
         refused root and fail closed - identical in spirit to the
         forbidden-root and clobbered-root throws at the IN_PLACE entry.
         Covers every present and future root-kill reason in one check.
         GHSA-6688-9rhm-gjv2 */
      let rootWasRemoved = false;
      arrayForEach(DOMPurify.removed, (entry) => {
        if (entry.element === dirty) {
          rootWasRemoved = true;
        }
      });

      if (rootWasRemoved) {
        _neutralizeSubtree(dirty);
        throw typeErrorCreate(
          'a node selected for removal could not be safely returned; ' +
            'refusing to sanitize in place'
        );
      }

      if (SAFE_FOR_TEMPLATES) {
        _scrubTemplateExpressions(dirty);
      }

      return dirty;
    }

    /* Return sanitized string or DOM */
    if (RETURN_DOM) {
      if (SAFE_FOR_TEMPLATES) {
        _scrubTemplateExpressions(body);
      }

      if (RETURN_DOM_FRAGMENT) {
        returnNode = createDocumentFragment.call(body.ownerDocument);

        while (body.firstChild) {
          // eslint-disable-next-line unicorn/prefer-dom-node-append
          returnNode.appendChild(body.firstChild);
        }
      } else {
        returnNode = body;
      }

      if (ALLOWED_ATTR.shadowroot || ALLOWED_ATTR.shadowrootmod) {
        /*
          AdoptNode() is not used because internal state is not reset
          (e.g. the past names map of a HTMLFormElement), this is safe
          in theory but we would rather not risk another attack vector.
          The state that is cloned by importNode() is explicitly defined
          by the specs.
        */
        returnNode = importNode.call(originalDocument, returnNode, true);
      }

      return returnNode;
    }

    let serializedHTML = WHOLE_DOCUMENT ? body.outerHTML : body.innerHTML;

    /* Serialize doctype if allowed */
    if (
      WHOLE_DOCUMENT &&
      ALLOWED_TAGS['!doctype'] &&
      body.ownerDocument &&
      body.ownerDocument.doctype &&
      body.ownerDocument.doctype.name &&
      regExpTest(EXPRESSIONS.DOCTYPE_NAME, body.ownerDocument.doctype.name)
    ) {
      serializedHTML =
        '<!DOCTYPE ' + body.ownerDocument.doctype.name + '>\n' + serializedHTML;
    }

    /* Sanitize final string template-safe */
    if (SAFE_FOR_TEMPLATES) {
      serializedHTML = stringReplace(serializedHTML, MUSTACHE_EXPR, ' ');
      serializedHTML = stringReplace(serializedHTML, ERB_EXPR, ' ');
      serializedHTML = stringReplace(serializedHTML, TMPLIT_EXPR, ' ');
    }

    return trustedTypesPolicy && RETURN_TRUSTED_TYPE
      ? trustedTypesPolicy.createHTML(serializedHTML)
      : serializedHTML;
  };

  /**
   * Public method to set the configuration once
   * setConfig
   *
   * @param {Object} cfg configuration object
   */
  DOMPurify.setConfig = function (cfg) {
    _parseConfig(cfg);
    SET_CONFIG = true;
  };

  /**
   * Public method to remove the configuration
   * clearConfig
   *
   */
  DOMPurify.clearConfig = function () {
    CONFIG = null;
    SET_CONFIG = false;
    PRISTINE_ALLOWED_TAGS = null;
    PRISTINE_ALLOWED_ATTR = null;
  };

  /**
   * Public method to check if an attribute value is valid.
   * Uses last set config, if any. Otherwise, uses config defaults.
   * isValidAttribute
   *
   * @param  {string} tag Tag name of containing element.
   * @param  {string} attr Attribute name.
   * @param  {string} value Attribute value.
   * @return {Boolean} Returns true if `value` is valid. Otherwise, returns false.
   */
  DOMPurify.isValidAttribute = function (tag, attr, value) {
    /* Initialize shared config vars if necessary. */
    if (!CONFIG) {
      _parseConfig({});
    }

    const lcTag = transformCaseFunc(tag);
    const lcName = transformCaseFunc(attr);
    return _isValidAttribute(lcTag, lcName, value);
  };

  /**
   * AddHook
   * Public method to add DOMPurify hooks
   *
   * @param {String} entryPoint entry point for the hook to add
   * @param {Function} hookFunction function to execute
   */
  DOMPurify.addHook = function (entryPoint, hookFunction) {
    if (typeof hookFunction !== 'function') {
      return;
    }

    hooks[entryPoint] = hooks[entryPoint] || [];
    arrayPush(hooks[entryPoint], hookFunction);
  };

  /**
   * RemoveHook
   * Public method to remove a DOMPurify hook at a given entryPoint
   * (pops it from the stack of hooks if more are present)
   *
   * @param {String} entryPoint entry point for the hook to remove
   * @return {Function} removed(popped) hook
   */
  DOMPurify.removeHook = function (entryPoint) {
    if (hooks[entryPoint]) {
      return arrayPop(hooks[entryPoint]);
    }
  };

  /**
   * RemoveHooks
   * Public method to remove all DOMPurify hooks at a given entryPoint
   *
   * @param  {String} entryPoint entry point for the hooks to remove
   */
  DOMPurify.removeHooks = function (entryPoint) {
    if (hooks[entryPoint]) {
      hooks[entryPoint] = [];
    }
  };

  /**
   * RemoveAllHooks
   * Public method to remove all DOMPurify hooks
   *
   */
  DOMPurify.removeAllHooks = function () {
    hooks = {};
  };

  return DOMPurify;
}

export default createDOMPurify();
