(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined'
    ? (module.exports = factory())
    : typeof define === 'function' && define.amd
    ? define(factory)
    : ((global =
        typeof globalThis !== 'undefined' ? globalThis : global || self),
      (global.testSuite = factory()));
})(this, function () {
  return function testSuite(
    DOMPurify,
    window,
    sanitizationTestCases,
    xssTestCases
  ) {
    var document = window.document;
    var jQuery = window.jQuery;

    sanitizationTestCases.forEach((testCase) => {
      QUnit.test(`Sanitization test[${testCase.title}]`, (assert) => {
        assert.contains(
          DOMPurify.sanitize(testCase.payload),
          testCase.expected,
          `Payload: ${testCase.payload}`
        );
      });
    });

    // XSS tests: Native DOM methods (alert() should not be called)
    xssTestCases.forEach((testCase) => {
      QUnit.test(`XSS test: native[${testCase.title}]`, (assert) => {
        document.getElementById('qunit-fixture').innerHTML = DOMPurify.sanitize(
          testCase.payload
        );
        const done = assert.async();
        setTimeout(() => {
          assert.notEqual(window.xssed, true, 'alert() was called');
          // Teardown
          document.getElementById('qunit-fixture').innerHTML = '';
          window.xssed = false;
          done();
        }, 100);
      });
    });
    // XSS tests: jQuery (alert() should not be called)
    xssTestCases.forEach((testCase) => {
      QUnit.test(`XSS test: jQuery[${testCase.title}]`, (assert) => {
        jQuery('#qunit-fixture').html(DOMPurify.sanitize(testCase.payload));
        const done = assert.async();
        setTimeout(() => {
          assert.notEqual(window.xssed, true, 'alert() was called');
          // Teardown
          jQuery('#qunit-fixture').empty();
          window.xssed = false;
          done();
        }, 100);
      });
    });
    // document.write tests to handle FF's strange behavior
    xssTestCases.forEach((testCase) => {
      QUnit.test(
        `XSS test: document.write() into iframe[${testCase.title}]`,
        (assert) => {
          const done = assert.async();
          const iframe = document.createElement('iframe');
          iframe.src = 'about:blank';
          iframe.onload = function () {
            iframe.contentDocument.write(
              '<script>window.alert=function(){top.xssed=true;}</script>' +
                DOMPurify.sanitize(testCase.payload)
            );
            assert.notEqual(
              window.xssed,
              true,
              'alert() was called from document.write()'
            );
            window.xssed = false;
            iframe.parentNode.removeChild(iframe);
            done();
          };
          document.body.appendChild(iframe);
        }
      );
    });

    // Config-Flag Tests
    QUnit.test(
      'Config-Flag tests: KEEP_CONTENT + ALLOWED_TAGS / ALLOWED_ATTR',
      function (assert) {
        // KEEP_CONTENT + ALLOWED_TAGS / ALLOWED_ATTR
        assert.equal(
          DOMPurify.sanitize('<iframe>Hello</iframe>', { KEEP_CONTENT: false }),
          ''
        );
        assert.contains(
          DOMPurify.sanitize(
            '<a href="#">abc<b style="color:red">123</b><q class="cite">123</b></a>',
            {
              ALLOWED_TAGS: ['b', 'q'],
              ALLOWED_ATTR: ['style'],
              KEEP_CONTENT: true,
            }
          ),
          [
            'abc<b style="color:red">123</b><q>123</q>',
            'abc<b style="color: red;">123</b><q>123</q>',
          ]
        );
        assert.equal(
          DOMPurify.sanitize(
            '<a href="#">abc<b style="color:red">123</b><q class="cite">123</b></a>',
            {
              ALLOWED_TAGS: ['b', 'q'],
              ALLOWED_ATTR: ['style'],
              KEEP_CONTENT: false,
            }
          ),
          ''
        );
        assert.equal(
          DOMPurify.sanitize('<a href="#">abc</a>', {
            ALLOWED_TAGS: ['b', 'q'],
            KEEP_CONTENT: false,
          }),
          ''
        );
        assert.equal(
          DOMPurify.sanitize('<form><input name="parentNode"></form>', {
            ALLOWED_TAGS: ['input'],
            KEEP_CONTENT: true,
          }),
          '<input>'
        );
      }
    );
    QUnit.test('Config-Flag tests: ALLOW_SELF_CLOSE_IN_ATTR', function (assert) {
      // ALLOW_SELF_CLOSE_IN_ATTR
      assert.contains(
        DOMPurify.sanitize('<a href="#" class="foo <br/>">abc</a>', {
          ALLOW_SELF_CLOSE_IN_ATTR: false,
        }),
        ['<a href="#">abc</a>',	"<a class=\"foo &lt;br/&gt;\" href=\"#\">abc</a>"]

      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" class="foo <br/>">abc</a>', {
          ALLOW_SELF_CLOSE_IN_ATTR: true,
        }),
        ['<a class="foo <br/>" href="#">abc</a>', "<a class=\"foo &lt;br/&gt;\" href=\"#\">abc</a>"]
      );
    });
    QUnit.test('Config-Flag tests: ALLOW_DATA_ATTR', function (assert) {
      // ALLOW_DATA_ATTR
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-abc"="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-abc="foo">abc</a>', {
          ALLOW_DATA_ATTR: false,
        }),
        '<a href="#">abc</a>'
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-abc="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a data-abc="foo" href="#">abc</a>',
          '<a href="#" data-abc="foo">abc</a>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-abc-1-2-3="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a data-abc-1-2-3="foo" href="#">abc</a>',
          '<a href="#" data-abc-1-2-3="foo">abc</a>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-""="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-äöü="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a href="#" data-äöü="foo">abc</a>',
          '<a data-äöü="foo" href="#">abc</a>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-\u00B7._="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a data-\u00B7._="foo" href="#">abc</a>',
          '<a href="#">abc</a>',
          '<a href="#" data-·._="foo">abc</a>',
        ] // IE11 and Edge throw an InvalidCharacterError
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-\u00B5="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-evil="foo">abc</a>', {
          FORBID_ATTR: ['data-evil'],
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-evil="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
          FORBID_ATTR: ['data-evil'],
        }),
        '<a href="#">abc</a>'
      );
    });
    QUnit.test('Config-Flag tests: ADD_TAGS', function (assert) {
      // ADD_TAGS
      assert.equal(
        DOMPurify.sanitize('<my-component>abc</my-component>', {
          ADD_TAGS: ['my-component'],
        }),
        '<my-component>abc</my-component>'
      );
    });
    QUnit.test('Config-Flag tests: ADD_TAGS + ADD_ATTR', function (assert) {
      // ADD_TAGS + ADD_ATTR
      assert.equal(
        DOMPurify.sanitize('<my-component my-attr="foo">abc</my-component>', {
          ADD_TAGS: ['my-component'],
        }),
        '<my-component>abc</my-component>'
      );
      assert.equal(
        DOMPurify.sanitize('<my-component my-attr="foo">abc</my-component>', {
          ADD_TAGS: ['my-component'],
          ADD_ATTR: ['my-attr'],
        }),
        '<my-component my-attr="foo">abc</my-component>'
      );
    });
    QUnit.test(
      'Config-Flag tests: FORBID_CONTENTS + FORBID_TAGS',
      function (assert) {
        // FORBID_CONTENTS + FORBID_TAGS
        assert.equal(
          DOMPurify.sanitize(
            '<div><b>preserve me</b></div><p><b>no not preserve me</b></p>',
            { FORBID_CONTENTS: ['p'], FORBID_TAGS: ['div', 'p'] }
          ),
          '<b>preserve me</b>'
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_JQUERY (now inactive, secure by default)',
      function (assert) {
        assert.equal(
          DOMPurify.sanitize(
            '<a>123</a><option><style><img src=x onerror=alert(1)>'
          ),
          '<a>123</a><option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<a>123</a><option><style><img src=x onerror=alert(1)>'
          ),
          '<a>123</a><option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<option><style></option></select><b><img src=xx: onerror=alert(1)></style></option>'
          ),
          '<option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<option><iframe></select><b><script>alert(1)</script>'
          ),
          '<option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<option><iframe></select><b><script>alert(1)</script>'
          ),
          '<option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<b><style><style/><img src=xx: onerror=alert(1)>'
          ),
          '<b></b>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<b><style><style/><img src=xx: onerror=alert(1)>'
          ),
          '<b></b>'
        );
        assert.contains(
          DOMPurify.sanitize('1<template><s>000</s></template>2'),
          ['1<template><s>000</s></template>2', '1<template></template>2', '12']
        );
        assert.contains(DOMPurify.sanitize('<template><s>000</s></template>'), [
          '',
          '<template><s>000</s></template>',
        ]);
        // see https://github.com/cure53/DOMPurify/issues/283
        assert.equal(
          DOMPurify.sanitize('<i>&amp;amp; &lt;</i>'),
          '<i>&amp;amp; &lt;</i>'
        );
      }
    );
    QUnit.test('Config-Flag tests: SAFE_FOR_TEMPLATES', function (assert) {
      //SAFE_FOR_TEMPLATES
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{456}}<b><style><% alert(1) %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a data-bind="style: alert(1)"></a>', {
          SAFE_FOR_TEMPLATES: true,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a data-harmless=""></a>', {
          SAFE_FOR_TEMPLATES: true,
          ALLOW_DATA_ATTR: true,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a data-harmless=""></a>', {
          SAFE_FOR_TEMPLATES: false,
          ALLOW_DATA_ATTR: false,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>{{123}}{{456}}<b><style><% alert(1) %><% 123 %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>{{123}}abc{{456}}<b><style><% alert(1) %>def<% 123 %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{45{{6}}<b><style><% alert(1)%> %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{45}}6}}<b><style><% <%alert(1) %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{<b>456}}</b><style><% alert(1) %></style>456</a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a>123 <b> </b><style> </style>456</a>'
      );
      assert.contains(
        DOMPurify.sanitize(
          '<b>{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}</b>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        ['<b>  </b>', '<b> </b>', '<b> <form><img src="x"></form> </b>']
      );
      assert.contains(
        DOMPurify.sanitize(
          '<b>he{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}ya</b>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        [
          '<b>he  ya</b>',
          '<b>he </b>',
          '<b>he <form><img src="x"></form> ya</b>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123<% <b>456}}</b><style>{{ alert(1) }}</style>456 %></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a>123 <b> </b><style> </style> </a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="}}javascript:alert(1)"></a>', {
          SAFE_FOR_TEMPLATES: true,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a class="{{999-333}}"></a>', {
          SAFE_FOR_TEMPLATES: true,
        }),
        '<a class=" "></a>'
      );
      assert.equal(
        DOMPurify.sanitize('{{999-333}}', { SAFE_FOR_TEMPLATES: true }),
        ' '
      );
      assert.equal(
        DOMPurify.sanitize('{<x>{333+333}<x>}', { SAFE_FOR_TEMPLATES: true }),
        ' '
      );
    });
    QUnit.test('Config-Flag tests: SANITIZE_DOM', function (assert) {
      // SANITIZE_DOM
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="implementation">', {
          SANITIZE_DOM: true,
        }),
        '<img src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="createNodeIterator">', {
          SANITIZE_DOM: true,
        }),
        '<img src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="getElementById">', {
          SANITIZE_DOM: false,
        }),
        '<img name="getElementById" src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="getElementById">', {
          SANITIZE_DOM: true,
        }),
        '<img src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="x" id="location">click</a>', {
          SANITIZE_DOM: true,
        }),
        '<a href="x">click</a>'
      );
      assert.contains(
        DOMPurify.sanitize('<form><input name="attributes"></form>', {
          ADD_TAGS: ['form'],
          SANITIZE_DOM: false,
        }),
        ['', '<form><input name="attributes"></form>']
      );
      assert.contains(
        DOMPurify.sanitize('<form><input name="attributes"></form>', {
          ADD_TAGS: ['form'],
          SANITIZE_DOM: true,
        }),
        ['', '<form><input name="attributes"></form>', '<form><input></form>']
      );
    });
    QUnit.test('Config-Flag tests: SANITIZE_NAMED_PROPS', function (assert) {
      // SANITIZE_NAMED_PROPS
      assert.equal(
        DOMPurify.sanitize('<a id="x"></a>', {
          SANITIZE_NAMED_PROPS: true,
        }),
        '<a id="user-content-x"></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<form id="x"><input id="y"></form>', {
          SANITIZE_NAMED_PROPS: true,
        }),
        '<form id="user-content-x"><input id="user-content-y"></form>'
      );
      assert.equal(
        DOMPurify.sanitize('<a id="x"></a><a id="x"></a>', {
          SANITIZE_NAMED_PROPS: true,
        }),
        '<a id="user-content-x"></a><a id="user-content-x"></a>'
      );
    });
    QUnit.test('Config-Flag tests: WHOLE_DOCUMENT', function (assert) {
      //WHOLE_DOCUMENT
      assert.equal(DOMPurify.sanitize('123', { WHOLE_DOCUMENT: false }), '123');
      assert.equal(
        DOMPurify.sanitize('123', { WHOLE_DOCUMENT: true }),
        '<html><head></head><body>123</body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: false,
        }),
        ''
      );
      assert.equal(
        DOMPurify.sanitize('<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: true,
        }),
        '<html><head><style>*{color:red}</style></head><body></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('123<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: false,
        }),
        '123<style>*{color:red}</style>'
      );
      assert.equal(
        DOMPurify.sanitize('123<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: true,
        }),
        '<html><head></head><body>123<style>*{color:red}</style></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<!DOCTYPE html><html><body>123</body></html>', {
          WHOLE_DOCUMENT: true,
        }),
        '<html><head></head><body>123</body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<!DOCTYPE html><html><body>123</body></html>', {
          WHOLE_DOCUMENT: true,
          ADD_TAGS: ['!doctype'],
        }),
        '<!DOCTYPE html>\n<html><head></head><body>123</body></html>'
      );
    });
    QUnit.test('Config-Flag tests: RETURN_DOM', function (assert) {
      //RETURN_DOM
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', { RETURN_DOM: true })
          .outerHTML,
        '<body><a>123<b>456</b></a></body>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>', {
          RETURN_DOM: true,
        }).outerHTML,
        '<body><a>123<b>456</b></a></body>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', {
          RETURN_DOM: true,
          WHOLE_DOCUMENT: true,
        }).outerHTML,
        '<html><head></head><body><a>123<b>456</b></a></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>', {
          RETURN_DOM: true,
          WHOLE_DOCUMENT: true,
        }).outerHTML,
        '<html><head></head><body><a>123<b>456</b></a></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('123', { RETURN_DOM: true }).outerHTML,
        '<body>123</body>'
      );
    });
    QUnit.test('Config-Flag tests: shadowroot', function (assert) {
      assert.notEqual(
        DOMPurify.sanitize('123', {
          RETURN_DOM: true,
        }).ownerDocument,
        document
      );
      assert.equal(
        DOMPurify.sanitize('123', {
          RETURN_DOM: true,
          ADD_ATTR: ['shadowroot'],
        }).ownerDocument,
        document
      );
      assert.notEqual(
        DOMPurify.sanitize('123', {
          RETURN_DOM_FRAGMENT: true,
        }).ownerDocument,
        document
      );
      assert.equal(
        DOMPurify.sanitize('123', {
          RETURN_DOM_FRAGMENT: true,
          ADD_ATTR: ['shadowroot'],
        }).ownerDocument,
        document
      );
    });
    QUnit.test('Config-Flag tests: RETURN_DOM_FRAGMENT', function (assert) {
      //RETURN_DOM_FRAGMENT
      // attempt clobbering
      var fragment = DOMPurify.sanitize(
        'foo<img id="createDocumentFragment">',
        {
          RETURN_DOM_FRAGMENT: true,
        }
      );
      assert.equal(fragment.nodeType, 11);
      assert.notEqual(fragment.ownerDocument, document);
      assert.equal(fragment.firstChild && fragment.firstChild.nodeValue, 'foo');
      // again, but without SANITIZE_DOM
      fragment = DOMPurify.sanitize('foo<img id="createDocumentFragment">', {
        RETURN_DOM_FRAGMENT: true,
        SANITIZE_DOM: false,
      });
      assert.equal(fragment.nodeType, 11);
      assert.notEqual(fragment.ownerDocument, document);
      assert.equal(fragment.firstChild && fragment.firstChild.nodeValue, 'foo');
    });
    QUnit.test('Config-Flag tests: RETURN_DOM_FRAGMENT', function (assert) {
      var xss = `<body><div><template shadowroot=open><img src=x onerror=alert(3)></template></div></body>`;
      var dom_body = DOMPurify.sanitize(xss, { RETURN_DOM: true });
      assert.equal(
        dom_body.outerHTML,
        '<body><div><template><img src="x"></template></div></body>'
      );
    });
    QUnit.test('Config-Flag tests: IN_PLACE', function (assert) {
      //IN_PLACE
      var dirty = document.createElement('a');
      dirty.setAttribute('href', 'javascript:alert(1)');
      var clean = DOMPurify.sanitize(dirty, { IN_PLACE: true });
      assert.equal(dirty, clean); // should return the input node
      assert.equal(dirty.href, ''); // should still sanitize
    });
    QUnit.test(
      'Config-Flag tests: IN_PLACE insecure root-nodes',
      function (assert) {
        //IN_PLACE with insecure root node (script)
        var dirty = document.createElement('script');
        dirty.setAttribute('src', 'data:,alert(1)');
        assert.throws(function () {
          DOMPurify.sanitize(dirty, { IN_PLACE: true });
        });
      }
    );
    QUnit.test(
      'Config-Flag tests: IN_PLACE insecure root-nodes',
      function (assert) {
        //IN_PLACE with insecure root node (iframe)
        var dirty = document.createElement('iframe');
        dirty.setAttribute('src', 'javascript:alert(1)');
        assert.throws(function () {
          DOMPurify.sanitize(dirty, { IN_PLACE: true });
        });
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES strips boundary-spanning Mustache expressions in IN_PLACE mode',
      function (assert) {
        // Regression for the IN_PLACE counterpart of CVE-2026-41239.
        // Per-text-node scrubbing alone misses {{...}} whose halves sit on
        // either side of a stripped foreign element: each text node holds only
        // a single '{' or '}', so MUSTACHE_EXPR (which requires '{{' or '}}')
        // matches nothing. After sanitization removes the foreign element the
        // surrounding text fragments are adjacent, and the serialized
        // innerHTML — which is what a template-evaluating framework reads —
        // shows '{{...}}' as a single interpolatable expression.
        var dirty = document.createElement('div');
        dirty.innerHTML =
          '{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}';
        var clean = DOMPurify.sanitize(dirty, {
          SAFE_FOR_TEMPLATES: true,
          IN_PLACE: true,
        });
        assert.equal(dirty, clean, 'should return the input node');
        assert.notOk(
          /\{\{[\s\S]*\}\}/.test(dirty.innerHTML),
          'merged Mustache expression should be scrubbed'
        );
        assert.notOk(
          /constructor/.test(dirty.innerHTML),
          'expression body should not survive scrubbing'
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES strips boundary-spanning ERB and template literal expressions',
      function (assert) {
        // CVE-2026-41239: the final scrub applies every SAFE_FOR_TEMPLATES
        // expression (MUSTACHE_EXPR, ERB_EXPR and TMPLIT_EXPR), not just
        // Mustache, to the merged text of the DOM-returning code paths.
        var dirty = document.createElement('div');
        dirty.innerHTML = '$<foo></foo>{alert(1)}';
        DOMPurify.sanitize(dirty, { SAFE_FOR_TEMPLATES: true, IN_PLACE: true });
        assert.notOk(
          /\$\{/.test(dirty.textContent),
          'merged template literal expression should be scrubbed in IN_PLACE mode'
        );
        dirty = document.createElement('div');
        dirty.innerHTML = '&lt;<foo></foo>% alert(1) %<foo></foo>&gt;';
        DOMPurify.sanitize(dirty, { SAFE_FOR_TEMPLATES: true, IN_PLACE: true });
        assert.notOk(
          /<%|%>/.test(dirty.textContent),
          'merged ERB expression should be scrubbed in IN_PLACE mode'
        );
        var returnNode = DOMPurify.sanitize('$<foo></foo>{alert(1)}', {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        });
        assert.notOk(
          /\$\{/.test(returnNode.textContent),
          'merged template literal expression should be scrubbed in RETURN_DOM mode'
        );
        returnNode = DOMPurify.sanitize(
          '&lt;<foo></foo>% alert(1) %<foo></foo>&gt;',
          {
            SAFE_FOR_TEMPLATES: true,
            RETURN_DOM: true,
          }
        );
        assert.notOk(
          /<%|%>/.test(returnNode.textContent),
          'merged ERB expression should be scrubbed in RETURN_DOM mode'
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES pins RETURN_DOM_FRAGMENT scrub behavior',
      function (assert) {
        // RETURN_DOM_FRAGMENT was fixed alongside RETURN_DOM in CVE-2026-41239
        // (both scrub the sanitized body before it is returned). Pinning the
        // fragment path here so future refactors of the post-walk return
        // logic do not silently regress it.
        var result = DOMPurify.sanitize(
          '<div>{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}</div>',
          {
            SAFE_FOR_TEMPLATES: true,
            RETURN_DOM_FRAGMENT: true,
          }
        );
        var container = document.createElement('div');
        container.appendChild(result);
        assert.notOk(
          /\{\{[\s\S]*\}\}/.test(container.innerHTML),
          'merged Mustache expression should be scrubbed in fragment mode'
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES scrub does not reparse DOM-built markup',
      function (assert) {
        // CVE-2026-41239 (upstream 688d372e): the final template scrub must not
        // serialize the tree and write it back through innerHTML. A DOM-built
        // <style> whose text closes the element would reparse into a live,
        // never-sanitized <img onerror>. The <b> child keeps the <style> past
        // the namespace-confusion mXSS check so the scrub actually sees it.
        var payload = '</style><img src=x onerror=alert(1)>';
        var dirty = document.createElement('div');
        var style = document.createElement('style');
        style.appendChild(document.createTextNode(payload));
        style.appendChild(document.createElement('b'));
        dirty.appendChild(style);
        DOMPurify.sanitize(dirty, { SAFE_FOR_TEMPLATES: true, IN_PLACE: true });
        assert.equal(
          dirty.getElementsByTagName('img').length,
          0,
          'IN_PLACE scrub must not create elements'
        );
        assert.equal(dirty.firstChild, style, 'node references are kept');
        dirty = document.createElement('div');
        style = document.createElement('style');
        style.appendChild(document.createTextNode(payload));
        style.appendChild(document.createElement('b'));
        dirty.appendChild(style);
        var returnNode = DOMPurify.sanitize(dirty, {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        });
        assert.equal(
          returnNode.getElementsByTagName('img').length,
          0,
          'RETURN_DOM scrub must not create elements'
        );
        // Merged expressions are still scrubbed from text and comments
        dirty = document.createElement('div');
        dirty.innerHTML = '<p>{<foo></foo>{x}<foo></foo>}</p>';
        var p = dirty.firstChild;
        DOMPurify.sanitize(dirty, { SAFE_FOR_TEMPLATES: true, IN_PLACE: true });
        assert.equal(dirty.firstChild, p, 'node references are kept');
        assert.notOk(/\{\{/.test(dirty.innerHTML), 'expression is scrubbed');
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES scrubs split expressions in walked fragments',
      function (assert) {
        // CVE-2026-41239 (upstream fdfd5a3f): each fragment _sanitizeShadowDOM
        // walks is normalized and scrubbed once its walk is done, so the
        // halves of an expression split by a removed element do not rejoin.
        var template = document.createElement('template');
        if (!template.content || template.content.nodeType !== 11) {
          assert.ok(true, 'no template support');
          return;
        }

        var clean = DOMPurify.sanitize(
          '<template>{<foo></foo>{x()}<foo></foo>}</template>',
          { SAFE_FOR_TEMPLATES: true, RETURN_DOM: true, FORCE_BODY: true }
        );
        var content = clean.getElementsByTagName('template')[0].content;
        assert.notOk(/\{\{/.test(content.textContent), 'template content');
        // The fragment is already scrubbed when afterSanitizeShadowDOM runs
        var hookSawExpression = false;
        DOMPurify.addHook('afterSanitizeShadowDOM', function (fragment) {
          if (/\{\{/.test(fragment.textContent)) {
            hookSawExpression = true;
          }
        });
        try {
          DOMPurify.sanitize(
            '<template>{<foo></foo>{x()}<foo></foo>}</template>',
            { SAFE_FOR_TEMPLATES: true, FORCE_BODY: true }
          );
        } finally {
          DOMPurify.removeHooks('afterSanitizeShadowDOM');
        }

        assert.notOk(hookSawExpression, 'walked fragment is scrubbed');
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES scrubs template content after normalization',
      function (assert) {
        // CVE-2026-41239: NodeIterator does not enter <template>.content, so
        // the final scrub recurses into it explicitly (upstream fdfd5a3f).
        var template = document.createElement('template');
        if (!template.content || template.content.nodeType !== 11) {
          assert.ok(true, 'no template support');
          return;
        }

        var dirty = document.createElement('div');
        dirty.appendChild(template);
        var content = template.content;
        content.appendChild(document.createTextNode('{'));
        content.appendChild(document.createElement('foo'));
        content.appendChild(document.createTextNode('{x}'));
        content.appendChild(document.createElement('foo'));
        content.appendChild(document.createTextNode('}'));
        DOMPurify.sanitize(dirty, { SAFE_FOR_TEMPLATES: true, IN_PLACE: true });
        assert.notOk(
          /\{\{/.test(template.content.textContent),
          'merged expression inside template content is scrubbed'
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES with RETURN_DOM',
      function (assert) {
        // CVE-2026-41239: the expression halves only merge once the foreign
        // elements are stripped, so the returned body must be scrubbed too.
        var returnNode = DOMPurify.sanitize(
          '{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}',
          {
            SAFE_FOR_TEMPLATES: true,
            RETURN_DOM: true,
          }
        );
        assert.notOk(
          /\{\{[\s\S]*\}\}/.test(returnNode.innerHTML),
          'merged Mustache expression should be scrubbed in RETURN_DOM mode'
        );
        assert.notOk(
          /constructor/.test(returnNode.innerHTML),
          'expression body should not survive scrubbing'
        );
        // Same payload passed in as a DOM node
        var dirty = document.createElement('div');
        dirty.innerHTML =
          '{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}';
        returnNode = DOMPurify.sanitize(dirty, {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        });
        assert.notOk(
          /\{\{[\s\S]*\}\}/.test(returnNode.innerHTML),
          'merged Mustache expression should be scrubbed for DOM node input'
        );
        assert.notOk(
          /constructor/.test(returnNode.innerHTML),
          'expression body should not survive scrubbing for DOM node input'
        );
        // Same payload with the returned node imported into the document
        returnNode = DOMPurify.sanitize(
          '{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}',
          {
            SAFE_FOR_TEMPLATES: true,
            RETURN_DOM: true,
            ADD_ATTR: ['shadowroot'],
          }
        );
        assert.notOk(
          /\{\{[\s\S]*\}\}/.test(returnNode.innerHTML),
          'merged Mustache expression should be scrubbed for an imported node'
        );
        // Markup without template expressions is left intact
        returnNode = DOMPurify.sanitize('<a>123</a><b>456</b>', {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        });
        assert.equal(returnNode.innerHTML, '<a>123</a><b>456</b>');
      }
    );
    QUnit.test('Config-Flag tests: FORBID_TAGS', function (assert) {
      //FORBID_TAGS
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', { FORBID_TAGS: ['b'] }),
        '<a>123456</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>789', {
          FORBID_TAGS: ['a', 'b'],
        }),
        '123456789'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', { FORBID_TAGS: ['c'] }),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>789', {
          FORBID_TAGS: ['script', 'b'],
        }),
        '<a>123456</a>789'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', {
          ADD_TAGS: ['b'],
          FORBID_TAGS: ['b'],
        }),
        '<a>123456</a>'
      );
    });
    QUnit.test('Config-Flag tests: FORBID_ATTR', function (assert) {
      //FORBID_ATTR
      assert.equal(
        DOMPurify.sanitize('<a x="1">123<b>456</b></a>', {
          FORBID_ATTR: ['x'],
        }),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a class="0" x="1">123<b y="1">456<script>alert(1)</script></b></a>789',
          { FORBID_ATTR: ['x', 'y'] }
        ),
        '<a class="0">123<b>456</b></a>789'
      );
      assert.equal(
        DOMPurify.sanitize('<a y="1">123<b y="1" y="2">456</b></a>', {
          FORBID_ATTR: ['y'],
        }),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123<b x="1">456<script y="1">alert(1)</script></b></a>789',
          { FORBID_ATTR: ['x', 'y'] }
        ),
        '<a>123<b>456</b></a>789'
      );
    });
    QUnit.test(
      'Config-Param tests: CUSTOM_ELEMENT_HANDLING',
      function (assert) {
        //CUSTOM_ELEMENT_HANDLING
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: /^foo-/,
                attributeNameCheck: /baz/,
                allowCustomizedBuiltInElements: true,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is="foo-baz"></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: /^foo-/,
                attributeNameCheck: /baz/,
                allowCustomizedBuiltInElements: false,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is=""></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: /-bar$/,
                attributeNameCheck: /.+/,
                allowCustomizedBuiltInElements: true,
              },
            }
          ), // DOMPurify swaps the order of attributes here!
          '<foo-bar forbidden="true" baz="foobar"></foo-bar><div is=""></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: (tagName) => tagName.match(/^foo-/),
                attributeNameCheck: (attr) => attr.match(/baz/),
                allowCustomizedBuiltInElements: true,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is="foo-baz"></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: (tagName) => tagName.match(/-bar$/),
                attributeNameCheck: (attr) => attr.match(/baz/),
                allowCustomizedBuiltInElements: true,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is=""></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<my-paragraph><span slot="my-text">test</span></my-paragraph>',
            {
              CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /-/u },
            }
          ),
          '<my-paragraph><span slot="my-text">test</span></my-paragraph>'
        );
      }
    );
    QUnit.test('Test dirty being an array', function (assert) {
      assert.equal(
        DOMPurify.sanitize(['<a>123<b>456</b></a>']),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(['<img src=', 'x onerror=alert(1)>']),
        '<img src=",x">'
      );
    });
    // cross-check that document.write into iframe works properly
    QUnit.test('XSS test: document.write() into iframe', function (assert) {
      const done = assert.async();
      window.xssed = false;
      var iframe = document.createElement('iframe');
      iframe.src = 'about:blank';
      iframe.onload = function () {
        iframe.contentDocument.write(
          '<script>window.alert=function(){parent.xssed=true;}</script><script>alert(1);</script>'
        );
        assert.equal(window.xssed, true, 'alert() was called but not detected');
        window.xssed = false;
        iframe.parentNode.removeChild(iframe);
        done();
      };
      document.body.appendChild(iframe);
    });
    // Check for isSupported property
    QUnit.test('DOMPurify property tests', function (assert) {
      assert.equal(typeof DOMPurify.isSupported, 'boolean');
    });
    // Test with a custom window object
    QUnit.test('DOMPurify custom window tests', function (assert) {
      assert.strictEqual(typeof DOMPurify(null).version, 'string');
      assert.strictEqual(DOMPurify(null).isSupported, false);
      assert.strictEqual(DOMPurify(null).sanitize, undefined);
      assert.strictEqual(typeof DOMPurify({}).version, 'string');
      assert.strictEqual(DOMPurify({}).isSupported, false);
      assert.strictEqual(DOMPurify({}).sanitize, undefined);
      assert.strictEqual(
        typeof DOMPurify({ document: 'not really a document' }).version,
        'string'
      );
      assert.strictEqual(
        DOMPurify({ document: 'not really a document' }).isSupported,
        false
      );
      assert.strictEqual(
        DOMPurify({ document: 'not really a document' }).sanitize,
        undefined
      );
      assert.strictEqual(typeof DOMPurify(window).version, 'string');
      assert.strictEqual(typeof DOMPurify(window).sanitize, 'function');
    });
    // Test to prevent security issues with pre-clobbered DOM
    QUnit.test(
      'sanitize() should not throw if the original document is clobbered _after_ DOMPurify has been instantiated',
      function (assert) {
        var evilNode = document.createElement('div');
        evilNode.innerHTML =
          '<img id="implementation"><img id="createNodeIterator"><img id="importNode"><img id="createElement">';
        document.body.appendChild(evilNode);
        try {
          // tests implementation and createNodeIterator
          var resultPlain = DOMPurify.sanitize('123');
          // tests importNode
          var resultImport = DOMPurify.sanitize('123', {
            RETURN_DOM: true,
            ADD_ATTR: ['shadowroot'],
          });
          // tests createElement
          var resultBody = DOMPurify.sanitize('123<img id="body">');
        } finally {
          // clean up before doing the actual assertions, otherwise qunit/jquery/etc might blow up
          document.body.removeChild(evilNode);
        }
        assert.equal(resultPlain, '123');
        assert.equal(resultImport.ownerDocument, document);
        assert.equal(resultBody, '123<img>');
      }
    );
    // Test to check against a hang in MSIE (#89)
    QUnit.test(
      'sanitize() should not hang on MSIE when hook changes textContent',
      function (assert) {
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (node.nodeType && node.nodeType === document.TEXT_NODE) {
            node.textContent = 'foo';
          }
          return node;
        });
        var dirty =
          '<div><p>This is a beatufiul text</p><p>This is too</p></div>';
        var modified = '<div><p>foo</p><p>foo</p></div>';
        assert.equal(DOMPurify.sanitize(dirty), modified);
        DOMPurify.removeHooks('afterSanitizeElements');
      }
    );
    // Tests to ensure that a configuration can be set and cleared
    QUnit.test(
      'ensure that a persistent configuration can be set and cleared',
      function (assert) {
        var dirty = '<foobar>abc</foobar>';
        assert.equal(DOMPurify.sanitize(dirty), 'abc');
        DOMPurify.setConfig({ ADD_TAGS: ['foobar'] });
        assert.equal(DOMPurify.sanitize(dirty), '<foobar>abc</foobar>');
        DOMPurify.clearConfig();
        assert.equal(DOMPurify.sanitize(dirty), 'abc');
      }
    );
    // Test to ensure that a hook can add allowed tags / attributes on the fly
    QUnit.test(
      'ensure that a hook can add allowed tags / attributes on the fly',
      function (assert) {
        DOMPurify.addHook('uponSanitizeElement', function (node, data) {
          if (
            node.nodeName &&
            node.nodeName.match(/^\w+-\w+$/) &&
            !data.allowedTags[data.tagName]
          ) {
            data.allowedTags[data.tagName] = true;
          }
        });
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (
            data.attrName &&
            data.attrName.match(/^\w+-\w+$/) &&
            !data.allowedAttributes[data.attrName]
          ) {
            data.allowedAttributes[data.attrName] = true;
          }
        });
        var dirty =
          '<p>HE<iframe></iframe><is-custom onload="alert(1)" super-custom="test" />LLO</p>';
        var modified =
          '<p>HE<is-custom super-custom="test">LLO</is-custom></p>';
        assert.equal(DOMPurify.sanitize(dirty), modified);
        DOMPurify.removeHooks('uponSanitizeElement');
        DOMPurify.removeHooks('uponSanitizeAttribute');
      }
    );
    // Test to ensure that if input[type=file] is badlisted and flagged as an
    // attribute not to keep via hookEvent.keepAttr, it should be removed despite
    // it being an issue of being able to programmatically add it back in Safari.
    QUnit.test(
      'ensure that input[type=file] is removed via hookEvent keepAttr',
      function (assert) {
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (
            node.nodeName == 'INPUT' &&
            node.getAttribute('type') &&
            node.getAttribute('type') == 'file'
          ) {
            data.keepAttr = false;
          }
        });
        var dirty = '<input type="file" />';
        var modified = '<input>';
        if (window.name == 'nodejs') {
          assert.equal(DOMPurify.sanitize(dirty), modified);
        } else {
          assert.expect(0);
        }
        DOMPurify.removeHooks('uponSanitizeAttribute');
      }
    );

    // -----------------------------------------------------------------------
    // CVE-2026-65902 (GHSA-76mc-f452-cxcm) - hook-driven allowlist pollution.
    // The data.allowedTags / data.allowedAttributes fields handed to
    // uponSanitizeElement / uponSanitizeAttribute hooks are references to the
    // live ALLOWED_TAGS / ALLOWED_ATTR sets, which are the module-level
    // defaults when no explicit ALLOWED_TAGS / ALLOWED_ATTR is configured. A
    // hook writing data.allowedTags.script = true must not widen the
    // allowlists of later calls, even after removeAllHooks() and
    // clearConfig(). The sets are cloned per sanitize() call whenever such a
    // hook is registered, so the documented in-call widening keeps working.
    // Each test uses a fresh instance, as the bug under test is cross-call
    // pollution.
    // -----------------------------------------------------------------------
    var withFreshPurify = function (callback) {
      var purify = DOMPurify(window);
      try {
        callback(purify);
      } finally {
        purify.removeAllHooks();
        purify.clearConfig();
      }
    };

    QUnit.test(
      'CVE-2026-65902: baseline, <script> and onclick are stripped under default config',
      function (assert) {
        withFreshPurify(function (purify) {
          assert.equal(
            purify.sanitize('<svg><script>alert(1)</script></svg>'),
            '<svg></svg>',
            'fresh default sanitize strips <script>'
          );
          assert.equal(
            purify.sanitize('<a onclick="alert(1)">x</a>'),
            '<a>x</a>',
            'fresh default sanitize strips onclick'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: in-call widening via hook still works',
      function (assert) {
        withFreshPurify(function (purify) {
          purify.addHook('uponSanitizeElement', function (node, data) {
            if (data.tagName === 'is-custom') {
              data.allowedTags['is-custom'] = true;
            }
          });
          purify.addHook('uponSanitizeAttribute', function (node, data) {
            if (data.attrName === 'super-custom') {
              data.allowedAttributes['super-custom'] = true;
            }
          });

          var input = '<p>HE<is-custom super-custom="test">LLO</is-custom></p>';
          assert.equal(
            purify.sanitize(input),
            input,
            'guarded hook widens allowlist for matching element in-call'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: unguarded element hook does not poison subsequent default-config calls',
      function (assert) {
        withFreshPurify(function (purify) {
          purify.addHook('uponSanitizeElement', function (node, data) {
            // The leaky pattern: unconditionally widen
            data.allowedTags.script = true;
          });

          assert.equal(
            purify.sanitize('<svg><script>1</script></svg>'),
            '<svg><script>1</script></svg>',
            'in-call widening still works while hook is registered'
          );

          purify.removeAllHooks();
          purify.clearConfig();

          assert.equal(
            purify.sanitize('<svg><script>alert(1)</script></svg>'),
            '<svg></svg>',
            'default sanitize after element-hook removal strips <script>'
          );
          assert.equal(
            purify.sanitize('<svg><script>alert(1)</script></svg>', {}),
            '<svg></svg>',
            'explicit empty config after element-hook removal strips <script>'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: unguarded attribute hook does not poison subsequent default-config calls',
      function (assert) {
        withFreshPurify(function (purify) {
          purify.addHook('uponSanitizeAttribute', function (node, data) {
            data.allowedAttributes.onclick = true;
          });

          assert.ok(
            purify.sanitize('<a onclick="alert(1)">x</a>').indexOf('onclick') !==
              -1,
            'in-call widening still works for attribute hook'
          );

          purify.removeAllHooks();
          purify.clearConfig();

          assert.equal(
            purify.sanitize('<a onclick="alert(1)">x</a>'),
            '<a>x</a>',
            'default sanitize after attr-hook removal strips onclick'
          );
          assert.equal(
            purify.isValidAttribute('a', 'onclick', 'alert(1)'),
            false,
            'isValidAttribute does not report the widened attribute'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: hook installed mid-walk does not poison the default or setConfig allowlists',
      function (assert) {
        // The per-walk clone samples the hooks before the walk, so an
        // uponSanitize* hook added from beforeSanitizeElements would
        // otherwise see the shared sets by reference.
        withFreshPurify(function (purify) {
          var widenTags = function (node, data) {
            data.allowedTags.script = true;
          };

          var widenAttr = function (node, data) {
            data.allowedAttributes.onerror = true;
          };

          var install = function () {
            purify.removeHooks('beforeSanitizeElements');
            purify.addHook('uponSanitizeElement', widenTags);
            purify.addHook('uponSanitizeAttribute', widenAttr);
          };

          var check = function (label) {
            purify.removeAllHooks();
            purify.addHook('beforeSanitizeElements', install);
            purify.sanitize('<div><b>x</b><img src=x onerror=alert(1)></div>');
            purify.removeAllHooks();
            assert.equal(
              purify.sanitize(
                '<p><script>alert(1)</script><img src=x onerror=alert(1)></p>'
              ),
              '<p><img src="x"></p>',
              label
            );
          };

          check('default allowlists stay pristine');
          purify.setConfig({});
          check('setConfig allowlists stay pristine');
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: pollution does not cross instance boundaries',
      function (assert) {
        withFreshPurify(function (purify) {
          purify.addHook('uponSanitizeElement', function (node, data) {
            data.allowedTags.script = true;
          });
          purify.sanitize('<svg><script>alert(1)</script></svg>');

          var freshInstance = DOMPurify(window);
          assert.equal(
            freshInstance.sanitize('<svg><script>alert(1)</script></svg>'),
            '<svg></svg>',
            'fresh DOMPurify instance must not inherit poisoned defaults'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: read-only hook does not poison defaults',
      function (assert) {
        withFreshPurify(function (purify) {
          var sawScriptKey;
          purify.addHook('uponSanitizeElement', function (node, data) {
            if (sawScriptKey === undefined) {
              sawScriptKey = 'script' in data.allowedTags;
            }
          });

          purify.sanitize('<div><span>hi</span></div>');

          assert.strictEqual(
            sawScriptKey,
            false,
            'hook sees default allowlist with script NOT included'
          );

          purify.removeAllHooks();
          purify.clearConfig();

          assert.equal(
            purify.sanitize('<svg><script>alert(1)</script></svg>'),
            '<svg></svg>',
            'read-only hook does not poison defaults'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: multiple polluting calls do not accumulate state in defaults',
      function (assert) {
        withFreshPurify(function (purify) {
          purify.addHook('uponSanitizeElement', function (node, data) {
            data.allowedTags.script = true;
            data.allowedTags.iframe = true;
            data.allowedTags.object = true;
          });

          for (var i = 0; i < 10; i++) {
            purify.sanitize('<div></div>');
          }

          purify.removeAllHooks();
          purify.clearConfig();

          assert.equal(
            purify.sanitize('<svg><script>1</script></svg>'),
            '<svg></svg>',
            'script still stripped after 10 polluting calls'
          );
          assert.equal(
            purify.sanitize('<iframe src="x"></iframe>'),
            '',
            'iframe still stripped after 10 polluting calls'
          );
          assert.equal(
            purify.sanitize('<object data="x"></object>'),
            '',
            'object still stripped after 10 polluting calls'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: explicit cfg.ALLOWED_TAGS path is unaffected by hook mutation in other calls',
      function (assert) {
        withFreshPurify(function (purify) {
          purify.addHook('uponSanitizeElement', function (node, data) {
            data.allowedTags.script = true;
          });

          var withCfg = purify.sanitize(
            '<svg><script>alert(1)</script></svg>',
            { ALLOWED_TAGS: ['svg'] }
          );
          assert.ok(
            withCfg.indexOf('<script>') !== -1,
            'explicit-cfg call respects in-call hook widening: ' + withCfg
          );

          purify.removeAllHooks();
          purify.clearConfig();

          assert.equal(
            purify.sanitize('<svg><script>alert(1)</script></svg>'),
            '<svg></svg>',
            'default-cfg call after explicit-cfg+hook is unaffected'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: setConfig({}) path does not let a hook poison the defaults',
      function (assert) {
        // setConfig({}) binds the module defaults and sanitize() then skips
        // _parseConfig, so a guard living only in _parseConfig never runs.
        withFreshPurify(function (purify) {
          purify.setConfig({});
          purify.addHook('uponSanitizeElement', function (node, data) {
            data.allowedTags.script = true;
          });
          purify.addHook('uponSanitizeAttribute', function (node, data) {
            data.allowedAttributes.onclick = true;
          });

          assert.equal(
            purify.sanitize('<svg><script>1</script></svg>'),
            '<svg><script>1</script></svg>',
            'in-call widening still works under setConfig'
          );

          purify.removeAllHooks();
          assert.equal(
            purify.sanitize(
              '<svg><script>alert(1)</script></svg><a onclick="alert(2)">x</a>'
            ),
            '<svg></svg><a>x</a>',
            'later setConfig call after hook removal is clean'
          );

          purify.clearConfig();
          assert.equal(
            purify.sanitize(
              '<svg><script>alert(1)</script></svg><a onclick="alert(2)">x</a>'
            ),
            '<svg></svg><a>x</a>',
            'default call after clearConfig is clean'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: setConfig attribute hook does not poison later calls',
      function (assert) {
        withFreshPurify(function (purify) {
          purify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
          purify.addHook('uponSanitizeAttribute', function (node, data) {
            if (
              node.getAttribute &&
              node.getAttribute('data-trusted') === '1'
            ) {
              data.allowedAttributes.onerror = true;
            }
          });

          assert.ok(
            purify
              .sanitize('<img data-trusted="1" src="x" onerror="ok()">')
              .indexOf('onerror') !== -1,
            'in-call widening works for the trusted element under setConfig'
          );

          assert.equal(
            purify.sanitize('<img src="x" onerror="alert(1)">'),
            '<img src="x">',
            'untrusted call after trusted render strips onerror'
          );

          for (var i = 0; i < 5; i++) {
            assert.equal(
              purify.sanitize('<img src="x" onerror="alert(' + i + ')">'),
              '<img src="x">',
              'repeated untrusted call ' + i + ' stays clean'
            );
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: setConfig element hook does not poison later calls',
      function (assert) {
        withFreshPurify(function (purify) {
          purify.setConfig({ ALLOWED_TAGS: ['span'], ALLOWED_ATTR: [] });
          purify.addHook('uponSanitizeElement', function (node, data) {
            if (
              node.getAttribute &&
              node.getAttribute('data-trusted') === '1' &&
              data.allowedTags
            ) {
              data.allowedTags.img = true;
            }
          });

          purify.sanitize('<span data-trusted="1"><img src="x"></span>');

          assert.equal(
            purify.sanitize('<img src="x" onerror="alert(1)">'),
            '',
            'untrusted <img> not allowed after trusted render under setConfig'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: setConfig then clearConfig restores a clean state',
      function (assert) {
        withFreshPurify(function (purify) {
          purify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
          purify.addHook('uponSanitizeAttribute', function (node, data) {
            if (
              node.getAttribute &&
              node.getAttribute('data-trusted') === '1'
            ) {
              data.allowedAttributes.onerror = true;
            }
          });
          purify.sanitize('<img data-trusted="1" src="x" onerror="ok()">');

          purify.clearConfig();

          assert.equal(
            purify.sanitize('<img src="x" onerror="alert(1)">'),
            '<img src="x">',
            'default-cfg call after clearConfig strips onerror'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65902: reusing the config object handed to a hook does not carry over its widening',
      function (assert) {
        // Hooks receive the parsed config as third argument. Passing it back
        // to sanitize() makes _parseConfig return early without rebinding
        // the allowlists, which must not resurrect the previous call's
        // hook-widened copy.
        withFreshPurify(function (purify) {
          var hookConfig = null;
          purify.addHook('uponSanitizeElement', function (node, data, config) {
            hookConfig = config;
            data.allowedTags.script = true;
          });

          purify.sanitize('<svg><script>1</script></svg>');
          purify.removeAllHooks();

          assert.ok(hookConfig, 'hook received the parsed config');
          assert.equal(
            purify.sanitize('<svg><script>alert(1)</script></svg>', hookConfig),
            '<svg></svg>',
            'call reusing the hook config strips <script>'
          );
        });
      }
    );
    QUnit.test(
      'sanitize() should allow unknown protocols when ALLOW_UNKNOWN_PROTOCOLS is true',
      function (assert) {
        var dirty =
          '<div><a href="spotify:track:12345"><img src="cid:1234567"></a></div>';
        assert.equal(
          dirty,
          DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
        );
      }
    );

    QUnit.test(
      'sanitize() should not allow javascript when ALLOW_UNKNOWN_PROTOCOLS is true',
      function (assert) {
        var dirty =
          '<div><a href="javascript:alert(document.title)"><img src="cid:1234567"/></a></div>';
        var modified = '<div><a><img src="cid:1234567"></a></div>';
        assert.equal(
          modified,
          DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
        );
      }
    );

    QUnit.test(
      'Regression-Test to make sure #166 stays fixed',
      function (assert) {
        var dirty = '<p onFoo="123">HELLO</p>';
        var modified = '<p>HELLO</p>';
        assert.equal(
          modified,
          DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
        );
      }
    );

    // Test 1 to check if the element count in DOMPurify.removed is correct
    QUnit.test(
      'DOMPurify.removed should contain one element',
      function (assert) {
        var dirty =
          '<svg onload=alert(1)><filter><feGaussianBlur /></filter></svg>';
        DOMPurify.sanitize(dirty);
        assert.contains(DOMPurify.removed.length, [1, 2]); // IE removes two
      }
    );

    // Test 2 to check if the element count in DOMPurify.removed is correct
    QUnit.test(
      'DOMPurify.removed should contain two elements',
      function (assert) {
        var dirty =
          '1<script>alert(1)</script><svg onload=alert(1)><filter><feGaussianBlur /></filter></svg>';
        DOMPurify.sanitize(dirty);
        assert.contains(DOMPurify.removed.length, [2, 3]); // IE removed three
      }
    );

    // Test 3 to check if the element count in DOMPurify.removed is correct
    QUnit.test('DOMPurify.removed should be correct', function (assert) {
      var dirty = '<img src=x onerror="alert(1)">';
      DOMPurify.sanitize(dirty);
      assert.equal(DOMPurify.removed.length, 1);
    });

    // Test 4 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
      function (assert) {
        var dirty = '<a>123{{456}}</a>';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 1);
      }
    );

    // Test 5 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
      function (assert) {
        var dirty = '<a>123{{456}}<b>456{{789}}</b></a>';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 2);
      }
    );

    // Test 6 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
      function (assert) {
        var dirty = '<img src=1 width="{{123}}">';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 1);
      }
    );

    // Test 7 to check that DOMPurify.removed is correct
    QUnit.test('DOMPurify.removed should be correct', function (assert) {
      var dirty = '<option><iframe></select><b><script>alert(1)</script>';
      DOMPurify.sanitize(dirty);
      assert.equal(DOMPurify.removed.length, 1);
    });

    // Test 8 to check that DOMPurify.removed is correct if tags are clean
    QUnit.test(
      'DOMPurify.removed should not contain elements if tags are permitted',
      function (assert) {
        var dirty = '<a>123</a>';
        DOMPurify.sanitize(dirty);
        assert.equal(DOMPurify.removed.length, 0);
      }
    );

    // Test 9 to check that DOMPurify.removed is correct if the tags and attributes are clean
    QUnit.test(
      'DOMPurify.removed should not contain elements if all tags and attrs are permitted',
      function (assert) {
        var dirty = '<img src=x>';
        DOMPurify.sanitize(dirty);
        assert.equal(DOMPurify.removed.length, 0);
      }
    );

    // Test 10 to check that DOMPurify.removed does not have false positive elements in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should not contain elements for valid data in SAFE_FOR_TEMLATES mode',
      function (assert) {
        var dirty = '1';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 0);
      }
    );

    // Test 11 to check that DOMPurify.removed does not have false positive elements
    QUnit.test(
      'DOMPurify.removed should not contain elements for valid data',
      function (assert) {
        var dirty = '1';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
        });
        assert.equal(DOMPurify.removed.length, 0);
      }
    );
    // Tests to make sure that the node scanning feature delivers acurate results on all browsers
    QUnit.test(
      'DOMPurify should deliver acurate results when sanitizing nodes 1',
      function (assert) {
        var clean = DOMPurify.sanitize(document.createElement('td'));
        assert.equal(clean, '<td></td>');
      }
    );
    QUnit.test(
      'DOMPurify should deliver accurate results when sanitizing nodes 2',
      function (assert) {
        var clean = DOMPurify.sanitize(document.createElement('td'), {
          RETURN_DOM: true,
        });
        assert.equal(clean.outerHTML, '<body><td></td></body>');
      }
    );
    // Test to make sure that URI_safe attributes can be configured too
    QUnit.test(
      'DOMPurify should allow to define URI safe attributes',
      function (assert) {
        var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
          ALLOWED_ATTR: ['typeof'],
          ADD_URI_SAFE_ATTR: ['typeof'],
        });
        assert.equal(clean, '<b typeof="bla:h">123</b>');
      }
    );
    // Test to make sure that URI_safe attributes don't persist, see #327
    QUnit.test(
      'DOMPurify should not persist URI safe attributes',
      function (assert) {
        var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
          ALLOWED_ATTR: ['typeof'],
          ADD_URI_SAFE_ATTR: ['typeof'],
        });
        var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
          ALLOWED_ATTR: ['typeof'],
        });
        assert.equal(clean, '<b>123</b>');
      }
    );
    // Test to make sure that URI_safe attributes don't overwrite default, see #366
    QUnit.test(
      'DOMPurify should not overwrite default URI safe attributes',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<div poster="x:y" style="color: red">Test</div>',
          { ADD_URI_SAFE_ATTR: ['poster'] }
        );
        assert.contains(clean, [
          '<div style="color: red" poster="x:y">Test</div>',
          '<div style="color: red;" poster="x:y">Test</div>',
        ]);

        clean = DOMPurify.sanitize(
          '<div poster="x:y" style="color: red">Test</div>'
        );
        assert.contains(clean, [
          '<div style="color: red">Test</div>',
          '<div style="color: red;">Test</div>',
        ]);
      }
    );
    // Test to make sure that empty HTML doesn't return null on MSIE11 (#198)
    QUnit.test(
      "Empty HTML shouldn't return null on MSIE11 in RETURN_DOM_FRAGMENT mode",
      function (assert) {
        var clean = DOMPurify.sanitize('', {
          RETURN_DOM: true,
          RETURN_DOM_FRAGMENT: true,
        });
        assert.equal(typeof clean, 'object');
      }
    );
    // Tests to make sure that FORCE_BODY pushes elements to document.body (#199)
    QUnit.test(
      'FORCE_BODY needs to push some elements to document.body',
      function (assert) {
        var clean = DOMPurify.sanitize('<style>123</style>', {
          FORCE_BODY: true,
        });
        assert.equal(clean, '<style>123</style>');
      }
    );
    QUnit.test(
      'FORCE_BODY needs to push some elements to document.body',
      function (assert) {
        var clean = DOMPurify.sanitize('<script>123</script>', {
          FORCE_BODY: true,
          ADD_TAGS: ['script'],
        });
        assert.equal(clean, '<script>123</script>');
      }
    );
    QUnit.test(
      'FORCE_BODY needs to push some elements to document.body',
      function (assert) {
        var clean = DOMPurify.sanitize(' AAAAA', { FORCE_BODY: true });
        assert.equal(clean, ' AAAAA');
      }
    );
    QUnit.test(
      'Lack of FORCE_BODY still preserves leading whitespace',
      function (assert) {
        var clean = DOMPurify.sanitize(' <b>AAAAA</b>', { FORCE_BODY: false });
        assert.equal(clean, ' <b>AAAAA</b>');
      }
    );
    QUnit.test(
      'Lack of FORCE_BODY needs to push some elements to document.head',
      function (assert) {
        var clean = DOMPurify.sanitize('<style>123</style>', {
          FORCE_BODY: false,
        });
        assert.equal(clean, '');
      }
    );
    // Test to make sure that ALLOW_ARIA_ATTR is working as expected (#198)
    QUnit.test('Config-Flag tests: ALLOW_ARIA_ATTR', function (assert) {
      assert.contains(
        DOMPurify.sanitize('<a aria-abc="foo" href="#">abc</a>', {
          ALLOW_ARIA_ATTR: true,
        }),
        [
          '<a aria-abc="foo" href="#">abc</a>',
          '<a href="#" aria-abc="foo">abc</a>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-aöü="foo">abc</a>', {
          ALLOW_ARIA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-abc="foo">abc</a>', {
          ALLOW_ARIA_ATTR: false,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-äöü="foo">abc</a>', {
          ALLOW_ARIA_ATTR: false,
        }),
        '<a href="#">abc</a>'
      );
    });
    QUnit.test('Config-Flag tests: USE_PROFILES', function (assert) {
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { html: false } }),
        'HELLO'
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { html: true } }),
        '<h1>HELLO</h1>'
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math></math>', {
          USE_PROFILES: { html: true, mathMl: true },
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math><mi></mi></math>', {
          USE_PROFILES: { html: true, mathMl: true },
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math><mi></mi></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math><mi></mi></math>', {
          USE_PROFILES: { html: true, mathMl: true },
          FORBID_TAGS: ['mi'],
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math class="foo"><mi></mi></math>', {
          USE_PROFILES: { html: true, mathMl: true },
          FORBID_ATTR: ['class'],
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math><mi></mi></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { bogus: true } }),
        'HELLO'
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: 123 }),
        'HELLO'
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: [] }),
        'HELLO'
      );
      assert.contains(
        DOMPurify.sanitize('<svg><rect height="50"></rect></svg>', {
          USE_PROFILES: { svg: true },
        }),
        [
          '',
          '<svg><rect height="50"></rect></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><rect height="50" /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.contains(
        DOMPurify.sanitize(
          '<svg><feBlend in="SourceGraphic" mode="multiply" /></svg>',
          {
            USE_PROFILES: { svgFilters: true },
            ADD_TAGS: ['svg'],
          }
        ),
        [
          '<svg><feblend in="SourceGraphic" mode="multiply"></feblend></svg>',
          '<svg><feblend mode="multiply" in="SourceGraphic"></feblend></svg>',
          '<svg><feBlend mode="multiply" in="SourceGraphic"></feBlend></svg>',
          '<svg><feBlend mode="multiply" in="SourceGraphic"></feBlend></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><feBlend in="SourceGraphic" mode="multiply" /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.contains(
        DOMPurify.sanitize(
          '<svg><style>.some-class {fill: #fff}</style></svg>',
          {
            USE_PROFILES: { svg: true },
          }
        ),
        [
          '',
          '<svg><style>.some-class {fill: #fff}</style></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><style>.some-class {fill: #fff}</style></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<svg><text>SEE ME</text></svg>', {
          USE_PROFILES: { svg: true },
          KEEP_CONTENT: false,
        }),
        [
          '',
          '<svg><text>SEE ME</text></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><text>SEE ME</text></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<span>SEE ME</span>', {
          USE_PROFILES: { html: true },
          KEEP_CONTENT: false,
        }),
        '<span>SEE ME</span>'
      );
      assert.equal(
        DOMPurify.sanitize('<div></div>', {
          USE_PROFILES: { svg: true },
          ADD_TAGS: ['div'],
        }),
        '<div></div>'
      );
      assert.contains(
        DOMPurify.sanitize('<svg keep="me"></svg>', {
          USE_PROFILES: { svg: true },
          ADD_ATTR: ['keep'],
        }),
        [
          '',
          '<svg keep="me"></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" keep="me" />',
        ]
      );
    });
    QUnit.test(
      'Config-Flag tests: USE_PROFILES ALLOWED_ATTR is prototype-free',
      function (assert) {
        // Inherited Array.prototype members must not count as allowed attributes
        assert.equal(
          DOMPurify.sanitize('<img fill="x" map="x" filter="x" src="x">', {
            USE_PROFILES: {},
            ADD_TAGS: ['img'],
          }),
          '<img>'
        );
        assert.equal(
          DOMPurify.sanitize('<img fill="x" map="x" filter="x" src="x">', {
            USE_PROFILES: { html: false },
            ADD_TAGS: ['img'],
          }),
          '<img>'
        );

        // Persistent configuration and isValidAttribute() share the same set
        try {
          DOMPurify.setConfig({ USE_PROFILES: {}, ADD_TAGS: ['img'] });
          assert.equal(DOMPurify.isValidAttribute('img', 'map', 'x'), false);
          assert.equal(DOMPurify.sanitize('<img fill="x" src="x">'), '<img>');
        } finally {
          DOMPurify.clearConfig();
        }

        // Polluted Object.prototype must not allow event handlers
        var clean;
        try {
          Object.defineProperty(Object.prototype, 'onerror', {
            value: true,
            writable: true,
            configurable: true,
          });
          clean = DOMPurify.sanitize('<img src="x" onerror="alert(1)">', {
            USE_PROFILES: {},
            ADD_TAGS: ['img'],
            FORBID_ATTR: ['style'],
          });
        } finally {
          delete Object.prototype.onerror;
          DOMPurify.clearConfig();
        }

        assert.equal(clean, '<img>');
      }
    );
    QUnit.test('Config-Flag tests: ALLOWED_URI_REGEXP', function (assert) {
      var tests = [
        {
          test: '<img src="https://i.imgur.com/hkfpOUu.gifv">',
          expected: '<img src="https://i.imgur.com/hkfpOUu.gifv">',
        },
        {
          test: '<img src="http://i.imgur.com/WScAnHr.jpg">',
          expected: '<img src="http://i.imgur.com/WScAnHr.jpg">',
        },
        {
          test:
            '<img src="blob:https://localhost:3000/c4ea3ec6-9f22-4d08-af6f-d79e78a0a7a7">',
          expected: '<img>',
        },
        {
          test: '<a href="mailto:demo@example.com">demo</a>',
          expected: '<a>demo</a>',
        },
      ];
      tests.forEach(function (test) {
        var str = DOMPurify.sanitize(test.test, {
          ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i,
        });
        assert.equal(str, test.expected);
      });
    });
    QUnit.test(
      'Avoid freeze when using tables and ALLOW_TAGS',
      function (assert) {
        var clean = DOMPurify.sanitize('<table><tr><td></td></tr></table>', {
          ALLOW_TAGS: ['table', 'tr', 'td'],
        });
        assert.equal(clean, '<table><tbody><tr><td></td></tr></tbody></table>');
      }
    );
    QUnit.test(
      'Avoid XSS with ALLOW_TAGS permitting noembed, noscript',
      function (assert) {
        var clean = DOMPurify.sanitize(
          "a<noembed><p id='</noembed><img src=x onerror=alert(1)>'></p></noembed>",
          { ADD_TAGS: ['noembed'] }
        );
        assert.contains(clean, [
          'a<noembed><p id=\'</noembed><img src="x">\'&gt;<p></p>',
          'a',
          'a<noembed>&lt;p id=\'</noembed><img src="x">\'&gt;<p></p>',
          'a<noembed><p id="&lt;/noembed&gt;&lt;img src=x onerror=alert(1)&gt;"></p></noembed>',
          'a<noembed></noembed>',
          'a<img src="x">\'&gt;<p></p>',
        ]);
      }
    );
    QUnit.test(
      'Avoid mXSS in Chrome 77 and above using SVG',
      function (assert) {
        var clean = DOMPurify.sanitize('<svg></p><style><g title="</style>');
        assert.contains(clean, [
          '',
          '<svg></svg><p></p><style><g title="</style>',
          '<p></p><style><g title="</style>',
          '<svg></svg><p></p>',
          '<svg><style></style></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><style /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><style /></svg></svg>',
        ]);
      }
    );
    QUnit.test(
      'Avoid mXSS in Chrome 77 and above using HTML',
      function (assert) {
        var clean = DOMPurify.sanitize('<svg></p><title><a href="</title>qqq');
        assert.contains(clean, [
          '',
          '<svg></svg><p></p><title>&lt;a href="</title>qqq<img src="">"&gt;',
          '<svg></svg><p></p><title>&lt;a href="</title>qqq',
          '<p></p><title>&lt;a href="</title>qqq',
          '<svg></svg><p></p>qqq',
          '<svg><title></title></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><title /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><title /></svg></svg>',
        ]);
      }
    );
    QUnit.test(
      'Test for correct return value when RETURN_TRUSTED_TYPE is true',
      function (assert) {
        var clean = DOMPurify.sanitize('<b>hello goodbye</b>', {
          RETURN_TRUSTED_TYPE: true,
        });
        var type = typeof clean;
        assert.contains(type, ['TrustedHTML', 'string', 'object']);
      }
    );
    QUnit.test(
      'Test for correct return value when RETURN_TRUSTED_TYPE is false',
      function (assert) {
        var clean = DOMPurify.sanitize('<b>hello goodbye</b>', {
          RETURN_TRUSTED_TYPE: false,
        });
        var type = typeof clean;
        assert.equal(type, 'string');
      }
    );
    QUnit.test(
      'Test for correct return value when RETURN_TRUSTED_TYPE is not set',
      function (assert) {
        var clean = DOMPurify.sanitize('<b>hello goodbye</b>');
        var type = typeof clean;
        assert.equal(type, 'string');
      }
    );
    QUnit.test(
      'Test for DoS coming from table sanitization 1/2 See #365',
      function (assert) {
        var config = { FORBID_TAGS: ['tbody'] };
        var clean = DOMPurify.sanitize(
          '<table><tbody><tr><td>test</td></tr></tbody></table>',
          config
        );
        assert.equal(
          clean,
          '<table><tbody><tr><td>test</td></tr></tbody></table>'
        );
      }
    );
    QUnit.test(
      'Test for DoS coming from table sanitization 2/2 See #365',
      function (assert) {
        var config = {
          ALLOWED_TAGS: [
            'b',
            'strong',
            'i',
            'italic',
            'div',
            'p',
            'span',
            'ul',
            'li',
            'ol',
            'a',
            'img',
            'br',
            'tr',
            'td',
            'th',
            'table',
            'h1',
            'h2',
            'h3',
            'h4',
            'h5',
            'h6',
          ],
          ALLOW_DATA_ATTR: false,
          ALLOWED_ATTR: ['src', 'class', 'target', 'href'],
        };
        var clean = DOMPurify.sanitize(
          '<table><colgroup><col></col></colgroup><tbody><tr><td >test</td></tr></tbody></table>',
          config
        );
        assert.equal(
          clean,
          '<table><tbody><tr><td>test</td></tr></tbody></table>'
        );
      }
    );
    QUnit.test(
      'Test for less agressive mXSS handling, See #369',
      function (assert) {
        var config = {
          FORBID_TAGS: ['svg', 'math'],
        };
        var clean = DOMPurify.sanitize(
          '<b data-test="<span>content</span>"></b>',
          config
        );
        assert.contains(clean, [
          '<b data-test="<span>content</span>"></b>',
          '<b data-test="&lt;span&gt;content&lt;/span&gt;"></b>',
        ]);
      }
    );
    QUnit.test(
      'Test against mXSS using text integration points and removal 1/2',
      function (assert) {
        var config = {
          FORBID_TAGS: ['mi'],
        };
        var clean = DOMPurify.sanitize(
          '<math><mi><b><style><b title="</style><iframe onload&#x3d;alert(1)<!--"></style>',
          config
        );
        assert.contains(clean, [
          '<math><b><style><b title="</style></b></math>',
          '<math></math>',
          '',
        ]);
      }
    );
    QUnit.test(
      'Test against mXSS using text integration points and removal 2/2',
      function (assert) {
        var config = {
          ADD_TAGS: ['xmp'],
        };
        var clean = DOMPurify.sanitize(
          "x<noframes><svg><b><xmp><b title='</xmp><img>",
          config
        );
        assert.contains(clean, ['x']);
      }
    );
    QUnit.test(
      'Test against insecure behavior in jQUery v3.0 and newer 1/2',
      function (assert) {
        var config = {};
        var clean = DOMPurify.sanitize(
          '<img x="/><img src=x onerror=alert(1)>" y="<x">',
          config
        );
        assert.contains(clean, [
          '<img y="<x" x="/><img src=x onerror=alert(1)>">', // jsdom
          '<img y="<x">',
          '<img y="&lt;x">',
          '<img y="<x">',
          "<img x=\"/><img src=x onerror=alert(1)>\" y=\"<x\">",
		  "<img y=\"&lt;x\" x=\"/&gt;&lt;img src=x onerror=alert(1)&gt;\">"
        ]);
      }
    );
    QUnit.test(
      'Test against insecure behavior in jQUery v3.0 and newer 2/2',
      function (assert) {
        var config = {};
        var clean = DOMPurify.sanitize(
          "a<noscript><p id='><noscript /><img src=x onerror=alert(1)>'></noscript>",
          config
        );
        assert.contains(clean, [
          "a<noscript>&lt;p id='>&lt;noscript />&lt;img src=x onerror=alert(1)>'></noscript>", // jsdom
          'a<noscript><p></p></noscript>',
          'a<p></p>',
          'a',
        ]);
      }
    );
    QUnit.test(
      'Test against data URIs in anchors without proper config flag',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<a href="data:image/gif;base64,123">icon.gif</a>'
        );
        assert.equal(clean, '<a>icon.gif</a>');
      }
    );
    QUnit.test(
      'Test against data URIs in anchors using proper config flag',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<a href="data:image/gif;base64,123">icon.gif</a>',
          {
            ADD_DATA_URI_TAGS: ['a', 'b'],
          }
        );
        assert.equal(clean, '<a href="data:image/gif;base64,123">icon.gif</a>');
      }
    );
    QUnit.test(
      'Test against Unicode tag names and proper removal',
      function (assert) {
        var clean = DOMPurify.sanitize('<svg><blocKquote>foo</blocKquote>');
        assert.contains(clean, [
          '<svg></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]);

        var clean = DOMPurify.sanitize('<svg><blocKquote>foo</blocKquote>');
        assert.contains(clean, [
          '<svg></svg><blockquote>foo</blockquote>',
          '<svg><blockquote>foo</blockquote></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" /><blockquote>foo</blockquote>',
        ]);
      }
    );
    QUnit.test(
      'Test protection from prototype pollution attacks 1/2',
      function (assert) {
        const obj = JSON.parse(
          '{"ALLOWED_ATTR":["onerror","src"], "documentMode":9}'
        );
        try {
          for (let [k, v] of Object.entries(obj)) {
            Object.prototype[k] = v;
          }
        } catch (e) {}
        var clean = DOMPurify.sanitize('<img src=x onerror=alert(1)>');
        assert.equal(clean, '<img src="x">');
      }
    );
    QUnit.test(
      'Test protection from prototype pollution attacks 2/2',
      function (assert) {
        var obj = {};
        obj.__proto__.hasOwnProperty = Object;
        obj.constructor.prototype.ALLOWED_ATTR = ["src", "onerror"];
        var clean = DOMPurify.sanitize('<img src=x onerror=alert(1)>');
        assert.equal(clean, '<img src="x">');
      }
    );
    QUnit.test('Test if namespaces are properly enforced', function (assert) {
      var tests = [
        {
          test:
            '<svg><desc><canvas></canvas><textarea></textarea></desc></svg>',
          expected: [
            '<svg><desc></desc></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg"><desc></desc></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg" />',
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><desc /></svg>"
          ],
        },
        {
          test: '<svg><canvas></canvas><textarea></textarea></svg>',
          expected: [
            '<svg></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg" />',
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><title /></svg>"
          ],
        },
        {
          test: '<math><canvas></canvas><textarea></textarea></math>',
          expected: ['<math></math>'],
        },
        {
          test: '<math><mi><canvas></canvas><textarea></textarea></mi></math>',
          expected: [
            '<math><mi><canvas></canvas><textarea></textarea></mi></math>',
            '<math></math>',
          ],
        },
        {
          test: '<svg><math></math><title><math></math></title></svg>',
          expected: [
            '<svg><title></title></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg" />',
            '<svg xmlns="http://www.w3.org/2000/svg"><title></title></svg>',
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><title /></svg>"
          ],
        },
        {
          test: '<math><svg></svg><mi><svg></svg></mi></math>',
          expected: [
            '<math><mi><svg></svg></mi></math>',
            '<math><mi><svg xmlns="http://www.w3.org/2000/svg" /></mi></math>',
            '<math></math>',
          ],
        },
        {
          test: '<form><math><mi><mglyph></form><form>',
          expected: [
            '<form><math><mi><mglyph></mglyph></mi></math></form>',
            '<form><math></math></form>',
          ],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test);
        assert.contains(clean, test.expected);
      });
    });
    QUnit.test('Config-Flag tests: NAMESPACE', function (assert) {
      var tests = [
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [
            '<polyline points="0 0"></polyline>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0 0"/>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0,0" />',
            '',
          ],
        },
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: ['', '<polyline points="0 0"></polyline>'], // IE10
        },
        {
          test: '<mi></mi>',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: [
            '<mi></mi>',
            '<mi xmlns="http://www.w3.org/1998/Math/MathML"></mi>',
            '<mi xmlns="http://www.w3.org/1998/Math/MathML"/>',
            '<mi xmlns="http://www.w3.org/1998/Math/MathML" />',
            '',
          ],
        },
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: ['', '<polyline points="0 0"></polyline>'], // IE10
        },
        {
          test: '<mi></mi>',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: [''],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test, test.config);
        assert.contains(clean, test.expected);
      });
    });
    QUnit.test('Config-Flag tests: ALLOWED_NAMESPACES', function (assert) {
      const tests = [
        // Test when ALLOWED_NAMESPACES is not set, result is empty for XML with custom namespace
        {
          test:
            '<library xmlns="http://www.ibm.com/library"><name>Library 1</name></library>',
          config: {
            ALLOWED_TAGS: ['#text', 'library', 'name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected: '',
        },
        // Test with one custom namespace at the root (ie. all sub-nodes will inherit that namespace)
        {
          test:
            '<library xmlns="http://www.ibm.com/library"><name>Library 1</name><dirty onload="alert()" /></library>',
          config: {
            ALLOWED_NAMESPACES: ['http://www.ibm.com/library'],
            ALLOWED_TAGS: ['#text', 'library', 'name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<library xmlns="http://www.ibm.com/library"><name>Library 1</name></library>',
        },
        // Test with one custom namespace at sub-node (root will default to HTML_NAMESPACE and should be kept)
        {
          test:
            '<city><library xmlns="http://www.ibm.com/library"><name>Library 1</name><dirty onload="alert()" /></library></city>',
          config: {
            ALLOWED_NAMESPACES: ['http://www.w3.org/1999/xhtml', 'http://www.ibm.com/library'],
            ALLOWED_TAGS: ['#text', 'city', 'library', 'name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<city xmlns="http://www.w3.org/1999/xhtml"><library xmlns="http://www.ibm.com/library"><name>Library 1</name></library></city>',
        },
        // Test removal of namespaces not listed in ALLOWED_NAMESPACES when input has multiple namespaces
        {
          test:
            '<library xmlns="http://www.ibm.com/library" xmlns:bk="urn:loc.gov:books"><bk:name>Library 1</bk:name><dirty onload="alert()" /></library>',
          config: {
            ALLOWED_NAMESPACES: ['http://www.ibm.com/library'],
            ALLOWED_TAGS: ['library', 'bk:name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected: ['<library xmlns="http://www.ibm.com/library"/>', '<library xmlns="http://www.ibm.com/library" />']
        },
        // Test with multiple custom namespaces and prefixes in input
        {
          test:
            '<library xmlns="http://www.ibm.com/library" xmlns:bk="urn:loc.gov:books" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"><bk:name>Library 1<m:properties>Other Properties</m:properties></bk:name><dirty onload="alert()" /></library>',
          config: {
            ALLOWED_NAMESPACES: [
              'http://www.ibm.com/library',
              'urn:loc.gov:books',
              'http://schemas.microsoft.com/ado/2007/08/dataservices/metadata',
            ],
            ALLOWED_TAGS: ['#text', 'library', 'bk:name', 'm:properties'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<library xmlns="http://www.ibm.com/library"><bk:name xmlns:bk="urn:loc.gov:books">Library 1<m:properties xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">Other Properties</m:properties></bk:name></library>',
        },
        // Test removal of elements mentioned in FORBID_TAGS even if their namespaces are allow-listed
        {
          test:
            '<library xmlns="http://www.ibm.com/library" xmlns:bk="urn:loc.gov:books" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"><bk:name>Library 1<m:properties>Other Properties</m:properties></bk:name><dirty onload="alert()" /></library>',
          config: {
            ADD_TAGS: ['library', 'bk:name'],
            ALLOWED_NAMESPACES: [
              'http://www.ibm.com/library',
              'urn:loc.gov:books',
              'http://schemas.microsoft.com/ado/2007/08/dataservices/metadata',
            ],
            FORBID_TAGS: ['m:properties'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<library xmlns="http://www.ibm.com/library"><bk:name xmlns:bk="urn:loc.gov:books">Library 1</bk:name></library>',
        },
      ];
      tests.forEach(function (test) {
        assert.contains(DOMPurify.sanitize(test.test, test.config), test.expected);
      });
    });
    QUnit.test('Config-Flag tests: PARSER_MEDIA_TYPE', function (assert) {
      const tests = [
        {
          test: '<A href="#">invalid</A><a TITLE="title" href="#">valid</a>',
          expected: {
            '': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'Application/xhtml+xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'application/xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'application/xhtml+xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              'invalid<a xmlns="http://www.w3.org/1999/xhtml" href="#">valid</a>',
              'invalid<a xmlns="http://www.w3.org/1999/xhtml" href="#" TITLE="title">valid</a>',
            ],
            'text/html': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'text/xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
          },
        },
        {
          config: {
            WHOLE_DOCUMENT: true,
          },
          test: '<A href="#">invalid</A><a TITLE="title" href="#">valid</a>',
          expected: {
            'text/html': [
              '<html><head></head><body><a href="#">invalid</a><a href="#" title="title">valid</a></body></html>',
              '<html><head></head><body><a href="#">invalid</a><a title="title" href="#">valid</a></body></html>',
            ],
            'application/xhtml+xml': [
              '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>invalid<a href="#">valid</a></body></html>',
              '<html xmlns="http://www.w3.org/1999/xhtml"><head /><body>invalid<a href="#">valid</a></body></html>',
              '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>invalid<a href="#" TITLE="title">valid</a></body></html>',
            ],
          },
        },
      ];
      tests.forEach(function (test) {
        Object.keys(test.expected).forEach(function (type) {
          var config = test.config || {};
          config.PARSER_MEDIA_TYPE = type;
          var clean = DOMPurify.sanitize(test.test, config);
          assert.contains(clean, test.expected[type]);
        });
      });
    });

    QUnit.test(
      'Config-Flag tests: PARSER_MEDIA_TYPE + ALLOWED_TAGS/ALLOWED_ATTR',
      function (assert) {
        assert.contains(
          DOMPurify.sanitize(
            '<a href="#">abc</a><CustomTag customattr="bar" CustomAttr="foo"/>',
            {
              PARSER_MEDIA_TYPE: 'application/xhtml+xml',
              ALLOWED_TAGS: ['a', 'CustomTag'],
              ALLOWED_ATTR: ['href', 'CustomAttr'],
            }
          ),
          [
            '<a xmlns="http://www.w3.org/1999/xhtml" href="#">abc</a><CustomTag xmlns="http://www.w3.org/1999/xhtml" CustomAttr="foo"></CustomTag>',
            '<a xmlns="http://www.w3.org/1999/xhtml" href="#">abc</a><CustomTag xmlns="http://www.w3.org/1999/xhtml" CustomAttr="foo" customattr="foo"></CustomTag>',
            '<a xmlns="http://www.w3.org/1999/xhtml" href="#">abc</a><CustomTag xmlns="http://www.w3.org/1999/xhtml" CustomAttr="foo" />'
          ]
        );
      }
    );

    QUnit.test('Test invalid xml', function (assert) {
      var tests = [
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [''],
        },
        {
          test: '<!-->',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: ['', '<!-->'],
        },
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: [''],
        },
        {
          test: '<!-->',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: ['', '<!-->'],
        },
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: [''],
        },
        {
          test: '',
          config: {},
          expected: [''],
        },
        {
          test: '<!-->',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: ['', '<!-->'],
        },
        {
          test: '<!-->',
          config: {},
          expected: ['', '<!-->'],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test, test.config);
        assert.contains(clean, test.expected);
      });
    });

    QUnit.test(
      'Test namespace default to html after other namespace been used',
      function (assert) {
        var tests = [
          {
            test: '<br>',
            config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
            expected: ['', '<br>'],
          },
          {
            test: '<br>',
            config: {},
            expected: ['<br>'],
          },
        ];
        tests.forEach(function (test) {
          var clean = DOMPurify.sanitize(test.test, test.config);
          assert.contains(clean, test.expected);
        });
      }
    );

    QUnit.test('Test non-html input after empty input', function (assert) {
      var tests = [
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [''],
        },
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [
            '<polyline points="0 0"></polyline>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0 0"/>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0,0" />',
            '',
          ],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test, test.config);
        assert.contains(clean, test.expected);
      });
    });

    // -----------------------------------------------------------------------
    // CVE-2026-49459 (GHSA-r47g-fvhr-h676) - parent-less clobbered IN_PLACE
    // root keeps attacker-controlled attributes. _forceRemove can not detach
    // a root without a parent and _sanitizeAttributes skips clobbered nodes,
    // so sanitize() must refuse a clobbered IN_PLACE root instead.
    // -----------------------------------------------------------------------

    // Does this engine implement HTMLFormElement [LegacyOverrideBuiltIns]
    // named-property clobbering for the given name? (jsdom does not)
    var formClobbers = function (name, tagName, doc) {
      doc = doc || document;
      var form = doc.createElement('form');
      var control = doc.createElement(tagName || 'input');
      control.setAttribute('name', name);
      form.appendChild(control);
      return form[name] === control;
    };

    QUnit.test(
      'CVE-2026-49459: parent-less clobbered form root throws instead of returning the root with onmouseover intact',
      function (assert) {
        if (!formClobbers('nodeName')) {
          assert.ok(true, 'SKIP: no form clobbering in this engine');
          return;
        }

        // The report's PoC: parent-less <form onmouseover=...> with an
        // <input name="nodeName"> child that clobbers form.nodeName. The
        // throw IS the protection: by refusing to return the root, the
        // sanitizer makes it impossible for the caller to insert an
        // attacker-controlled element into the live DOM.
        var root = document.createElement('form');
        root.setAttribute('onmouseover', 'window.__rooted_h676 = 1');
        var clobber = document.createElement('input');
        clobber.setAttribute('name', 'nodeName');
        root.appendChild(clobber);

        var result = null;
        assert.throws(
          function () {
            result = DOMPurify.sanitize(root, { IN_PLACE: true });
          },
          /root node is clobbered/,
          'clobbered parent-less IN_PLACE root must throw'
        );
        assert.equal(result, null, 'no node is handed back to the caller');
      }
    );

    QUnit.test(
      'CVE-2026-49459: each clobbering name covered by _isClobbered triggers the IN_PLACE preamble throw',
      function (assert) {
        // Every name _isClobbered checks on this version. Any one of them
        // flags the root, which _forceRemove can't detach, so each must make
        // the IN_PLACE preamble throw.
        var clobberNames = [
          'nodeName',
          'textContent',
          'removeChild',
          'attributes',
          'removeAttribute',
          'setAttribute',
          'namespaceURI',
          'insertBefore',
          'hasChildNodes',
          'childNodes',
          'nodeType',
        ];

        for (var i = 0; i < clobberNames.length; i++) {
          var name = clobberNames[i];
          if (!formClobbers(name)) {
            assert.ok(true, 'SKIP: no form clobbering of "' + name + '"');
            continue;
          }

          var root = document.createElement('form');
          root.setAttribute('onmouseover', 'window.__rooted_' + name + ' = 1');
          root.setAttribute('action', 'javascript:alert(1)');
          var clobber = document.createElement('input');
          clobber.setAttribute('name', name);
          root.appendChild(clobber);

          assert.throws(
            function () {
              DOMPurify.sanitize(root, { IN_PLACE: true });
            },
            /root node is clobbered/,
            'IN_PLACE preamble must throw for clobber name="' + name + '"'
          );

          // Re-sanitizing the same node must still refuse it
          assert.throws(
            function () {
              DOMPurify.sanitize(root, {
                IN_PLACE: true,
                SAFE_FOR_TEMPLATES: true,
              });
            },
            /root node is clobbered/,
            'second IN_PLACE pass must throw for clobber name="' + name + '"'
          );
        }
      }
    );

    QUnit.test(
      'CVE-2026-49459: a parented clobbered form is still sanitized normally (regression guard)',
      function (assert) {
        if (!formClobbers('nodeName')) {
          assert.ok(true, 'SKIP: no form clobbering in this engine');
          return;
        }

        // When the IN_PLACE root is NOT the clobbered form (it's a wrapper
        // that contains it), the iterator-driven removal path works
        // normally: _forceRemove succeeds because the form has a parent.
        var wrapper = document.createElement('div');
        var form = document.createElement('form');
        form.setAttribute('onmouseover', 'window.__rooted_parented = 1');
        var clobber = document.createElement('input');
        clobber.setAttribute('name', 'nodeName');
        form.appendChild(clobber);
        wrapper.appendChild(form);

        DOMPurify.sanitize(wrapper, { IN_PLACE: true });

        assert.equal(
          wrapper.querySelectorAll('form').length,
          0,
          'parented clobbered form is removed by the iterator-driven path'
        );
      }
    );

    QUnit.test(
      'CVE-2026-49459: _isClobbered: form clobbered by an <input> or <select> named "childNodes" is removed during sanitization',
      function (assert) {
        // <select> defeats a naive `typeof childNodes.length === "number"`
        // probe because HTMLSelectElement.length is a defined unsigned-long
        // attribute returning the option count. The probe must instead
        // compare the direct read against the cached Node.prototype getter,
        // which is type-agnostic and catches every clobbering child.
        var tagNames = ['input', 'select'];
        for (var i = 0; i < tagNames.length; i++) {
          if (!formClobbers('childNodes', tagNames[i])) {
            assert.ok(true, 'SKIP: no form clobbering in this engine');
            continue;
          }

          var form = document.createElement('form');
          var clobber = document.createElement(tagNames[i]);
          clobber.setAttribute('name', 'childNodes');
          form.appendChild(clobber);

          var wrapper = document.createElement('div');
          wrapper.appendChild(form);

          DOMPurify.sanitize(wrapper, { IN_PLACE: true });

          assert.equal(
            wrapper.querySelectorAll('form').length,
            0,
            'form clobbered by <' + tagNames[i] + ' name="childNodes"> is removed'
          );
        }
      }
    );

    QUnit.test(
      'CVE-2026-49459: unclobbered IN_PLACE form root is still sanitized (regression guard)',
      function (assert) {
        var form = document.createElement('form');
        form.setAttribute('onmouseover', 'alert(1)');
        form.setAttribute('action', 'javascript:alert(2)');
        form.appendChild(document.createElement('input'));
        var clean = DOMPurify.sanitize(form, { IN_PLACE: true });
        assert.equal(clean, form, 'the root node itself is returned');
        assert.equal(
          form.hasAttribute('onmouseover'),
          false,
          'onmouseover removed'
        );
        assert.equal(
          form.hasAttribute('action'),
          false,
          'javascript: action removed'
        );
        assert.equal(form.querySelectorAll('input').length, 1, 'input kept');
        assert.equal(
          DOMPurify.sanitize('<form action="/x"><input name="q"></form>'),
          '<form action="/x"><input name="q"></form>',
          'string input keeps an unclobbered form'
        );
      }
    );

    QUnit.test(
      'CVE-2026-49459: engines without prototype DOM getters still sanitize (Safari < 10, Chrome < 43)',
      function (assert) {
        // Those engines keep nodeType, attributes, childNodes etc. on the
        // instance, so Node/Element.prototype has methods but no accessors.
        // Simulate one with prototypes that copy only the methods; real
        // nodes still answer direct reads.
        var legacyProto = function (proto) {
          var legacy = {};
          for (
            var p = proto;
            p && p !== Object.prototype;
            p = Object.getPrototypeOf(p)
          ) {
            var names = Object.getOwnPropertyNames(p);
            for (var i = 0; i < names.length; i++) {
              var desc = Object.getOwnPropertyDescriptor(p, names[i]);
              if (
                !(names[i] in legacy) &&
                desc &&
                typeof desc.value === 'function'
              ) {
                legacy[names[i]] = desc.value;
              }
            }
          }

          return legacy;
        };

        var LegacyNode = function () {};
        LegacyNode.prototype = legacyProto(window.Node.prototype);
        // On those engines `node instanceof Node` still holds for nodes of
        // the same window; keep that for the stub constructor where possible.
        var keepsInstanceof =
          typeof Symbol === 'function' &&
          typeof Symbol.hasInstance === 'symbol';
        if (keepsInstanceof) {
          Object.defineProperty(LegacyNode, Symbol.hasInstance, {
            value: function (object) {
              return object instanceof window.Node;
            },
          });
        }

        var LegacyElement = function () {};
        LegacyElement.prototype = legacyProto(window.Element.prototype);
        var legacyWindow = { Node: LegacyNode, Element: LegacyElement };
        var copied = [
          'document',
          'HTMLTemplateElement',
          'NodeFilter',
          'DOMParser',
          'NamedNodeMap',
          'MozNamedAttrMap',
          'DocumentFragment',
          'HTMLFormElement',
        ];
        for (var i = 0; i < copied.length; i++) {
          legacyWindow[copied[i]] = window[copied[i]];
        }

        var purify = DOMPurify(legacyWindow);
        assert.equal(
          purify.sanitize('<b>x</b><img src=x onerror=alert(1)>'),
          '<b>x</b><img src="x">',
          'string input is sanitized, not emptied'
        );
        assert.equal(
          purify.sanitize('<form><input name="q"></form>'),
          '<form><input name="q"></form>',
          'an unclobbered form is not mistaken for a clobbered one'
        );
        var dirty = document.createElement('div');
        dirty.innerHTML =
          '<p onclick="alert(1)">ok</p><img src=x onerror=alert(1)>';
        purify.sanitize(dirty, { IN_PLACE: true });
        assert.equal(
          dirty.innerHTML,
          '<p>ok</p><img src="x">',
          'IN_PLACE input is sanitized, not refused'
        );
        // A clobbered form root is still refused through the getter-free
        // probes
        var form = document.createElement('form');
        form.setAttribute('onmouseover', 'alert(1)');
        form.innerHTML = '<input name="attributes"><input name="nodeType">';
        if (typeof form.nodeType === 'number' || !keepsInstanceof) {
          assert.ok(true, 'SKIP: engine does not clobber form properties');
          return;
        }

        assert.throws(function () {
          purify.sanitize(form, { IN_PLACE: true });
        }, /root node is clobbered/);
      }
    );

    // -----------------------------------------------------------------------
    // CVE-2026-49458 (GHSA-hpcv-96wg-7vj8) - nodes from another window/realm.
    // Security decisions keyed on `instanceof X` against this window's
    // constructors short-circuit for nodes minted in a same-origin iframe:
    // a foreign <form> was never recognized as clobbered, a foreign
    // <template>.content was never walked and a foreign element skipped the
    // namespace check.
    // -----------------------------------------------------------------------

    // Run callback with the document of a same-origin iframe, which is a
    // separate realm: its nodes are instances of the iframe window's
    // constructors, not of this window's.
    var withForeignDocument = function (assert, callback) {
      var iframe = document.createElement('iframe');
      document.body.appendChild(iframe);
      try {
        var foreignDocument = iframe.contentDocument;
        if (
          !foreignDocument ||
          foreignDocument.createElement('div') instanceof window.Element
        ) {
          assert.ok(true, 'SKIP: no separate iframe realm in this engine');
          return;
        }

        callback(foreignDocument);
      } finally {
        iframe.parentNode.removeChild(iframe);
      }
    };

    QUnit.test(
      'CVE-2026-49458: clobbered form of a same-origin iframe is refused as IN_PLACE root and removed below one',
      function (assert) {
        withForeignDocument(assert, function (foreignDocument) {
          // A clean foreign root is sanitized and handed back
          var root = foreignDocument.createElement('div');
          root.setAttribute('onmouseover', 'alert(1)');
          root.innerHTML = 'text<b onclick="alert(2)">bold</b>';
          var clean = DOMPurify.sanitize(root, { IN_PLACE: true });
          assert.equal(clean, root, 'the foreign root is returned');
          assert.equal(
            root.getAttribute('onmouseover'),
            null,
            'onmouseover on the foreign root is stripped'
          );
          assert.equal(
            root.innerHTML,
            'text<b>bold</b>',
            'children of the foreign root are sanitized'
          );

          if (!formClobbers('attributes', 'input', foreignDocument)) {
            assert.ok(true, 'SKIP: no form clobbering in this engine');
            return;
          }

          // The advisory's PoC 1: a foreign <form onmouseover> whose
          // .attributes is clobbered by a named <input>
          var form = foreignDocument.createElement('form');
          form.setAttribute('onmouseover', 'alert(3)');
          var clobber = foreignDocument.createElement('input');
          clobber.setAttribute('name', 'attributes');
          form.appendChild(clobber);
          assert.throws(
            function () {
              DOMPurify.sanitize(form, { IN_PLACE: true });
            },
            /root node is clobbered/,
            'clobbered foreign form root must throw on IN_PLACE'
          );

          // The same form below a foreign root is removed
          var wrapper = foreignDocument.createElement('div');
          wrapper.appendChild(form);
          DOMPurify.sanitize(wrapper, { IN_PLACE: true });
          assert.equal(
            wrapper.querySelectorAll('form').length,
            0,
            'clobbered foreign form below the root is removed'
          );
          assert.notOk(
            /onmouseover/.test(wrapper.innerHTML),
            'no handler survives: ' + wrapper.innerHTML
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-49458: <template> content of a same-origin iframe is sanitized in IN_PLACE mode',
      function (assert) {
        withForeignDocument(assert, function (foreignDocument) {
          // The advisory's PoC 2, plus a nested template that is only
          // reached through the _sanitizeShadowDOM recursion
          var root = foreignDocument.createElement('div');
          root.innerHTML =
            '<template><img src="x" onerror="alert(1)">' +
            '<template><img src="y" onerror="alert(2)"></template>' +
            '</template>';
          var template = root.firstChild;
          if (!template.content || !template.content.firstChild) {
            assert.ok(true, 'SKIP: no <template>.content in this engine');
            return;
          }

          DOMPurify.sanitize(root, { IN_PLACE: true });

          var img = template.content.firstChild;
          assert.equal(img.nodeName, 'IMG', 'template content is kept');
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror inside the foreign <template> is stripped'
          );
          var nested = template.content.lastChild.content.firstChild;
          assert.equal(nested.nodeName, 'IMG', 'nested content is kept');
          assert.equal(
            nested.getAttribute('onerror'),
            null,
            'onerror inside the nested foreign <template> is stripped'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-49458: element of a same-origin iframe in a foreign namespace is removed in IN_PLACE mode',
      function (assert) {
        withForeignDocument(assert, function (foreignDocument) {
          var root = foreignDocument.createElement('div');
          root.appendChild(
            foreignDocument.createElementNS('http://example.com/ns', 'div')
          );
          root.appendChild(
            foreignDocument.createElementNS('http://www.w3.org/2000/svg', 'p')
          );
          DOMPurify.sanitize(root, { IN_PLACE: true });
          assert.equal(
            root.childNodes.length,
            0,
            'elements in a namespace the parser never yields are removed'
          );
        });
      }
    );

    // The same realm mismatch, reproduced in every engine: the DOMPurify
    // instance below is built from a window whose constructors are not on
    // the prototype chain of this document's nodes, exactly like the
    // constructors of another realm, while the prototype getters stay the
    // real ones.
    var createForeignRealmPurify = function (NodeOverride) {
      var foreign = function (Real) {
        var Ctor = function () {};
        Ctor.prototype = Object.create(
          Real ? Real.prototype : Object.prototype
        );
        return Ctor;
      };

      return DOMPurify({
        document: document,
        DocumentFragment: foreign(window.DocumentFragment),
        HTMLTemplateElement: window.HTMLTemplateElement,
        Node: NodeOverride || foreign(window.Node),
        NodeFilter: window.NodeFilter,
        NamedNodeMap: foreign(window.NamedNodeMap || window.MozNamedAttrMap),
        Element: foreign(window.Element),
        HTMLFormElement: foreign(window.HTMLFormElement),
        DOMParser: window.DOMParser,
      });
    };

    QUnit.test(
      'CVE-2026-49458: foreign-realm IN_PLACE root, <template> content and namespaces are sanitized',
      function (assert) {
        var realmPurify = createForeignRealmPurify();

        var root = document.createElement('div');
        root.setAttribute('onmouseover', 'alert(1)');
        root.innerHTML = 'text<b onclick="alert(2)">bold</b>';
        var clean = realmPurify.sanitize(root, { IN_PLACE: true });
        assert.equal(clean, root, 'the input node is returned');
        assert.equal(
          root.getAttribute('onmouseover'),
          null,
          'onmouseover on the foreign-realm root is stripped'
        );
        assert.equal(
          root.innerHTML,
          'text<b>bold</b>',
          'children are sanitized'
        );

        // Pre-fix `content instanceof DocumentFragment` was false for the
        // foreign fragment, so the template body was never walked.
        assert.equal(
          realmPurify.sanitize(
            '<b onclick=alert(1)>a</b><template><img src=x onerror=alert(2)></template>'
          ),
          '<b>a</b><template><img src="x"></template>',
          'string input: template content is sanitized'
        );
        assert.equal(
          realmPurify.sanitize(
            '<b>a</b><template><template><img src=x onerror=alert(3)></template></template>'
          ),
          '<b>a</b><template><template><img src="x"></template></template>',
          'string input: nested template content is sanitized'
        );

        var wrapper = document.createElement('div');
        wrapper.innerHTML =
          '<template><img src="x" onerror="alert(4)"></template>';
        var template = wrapper.firstChild;
        if (template.content && template.content.firstChild) {
          realmPurify.sanitize(wrapper, { IN_PLACE: true });
          assert.equal(
            template.content.firstChild.getAttribute('onerror'),
            null,
            'IN_PLACE: onerror inside the foreign-realm <template> is stripped'
          );
        } else {
          assert.ok(true, 'SKIP: no <template>.content in this engine');
        }

        // Pre-fix `currentNode instanceof Element` was false, so the
        // namespace check was skipped for every element
        var nsRoot = document.createElement('div');
        nsRoot.appendChild(
          document.createElementNS('http://example.com/ns', 'div')
        );
        realmPurify.sanitize(nsRoot, { IN_PLACE: true });
        assert.equal(
          nsRoot.childNodes.length,
          0,
          'element in an unknown namespace is removed'
        );
      }
    );

    QUnit.test(
      'CVE-2026-49458: foreign-realm clobbered form is refused as IN_PLACE root and removed below one',
      function (assert) {
        // The cross-realm _isNode fallback reads nodeType through the cached
        // getter, so a clobbered form of another realm is still recognized
        // as a node and then refused by the IN_PLACE clobbering pre-flight
        // instead of being stringified and handed back untouched.
        var names = ['attributes', 'nodeType', 'nodeName', 'childNodes'];
        var realmPurify = createForeignRealmPurify();
        for (var i = 0; i < names.length; i++) {
          if (!formClobbers(names[i])) {
            assert.ok(true, 'SKIP: no form clobbering of "' + names[i] + '"');
            continue;
          }

          var form = document.createElement('form');
          form.setAttribute('onmouseover', 'alert(1)');
          var clobber = document.createElement('input');
          clobber.setAttribute('name', names[i]);
          form.appendChild(clobber);

          assert.throws(
            function () {
              realmPurify.sanitize(form, { IN_PLACE: true });
            },
            /root node is clobbered/,
            'foreign-realm form clobbered by name="' +
              names[i] +
              '" must throw'
          );

          var wrapper = document.createElement('div');
          wrapper.appendChild(form);
          realmPurify.sanitize(wrapper, { IN_PLACE: true });
          assert.equal(
            wrapper.querySelectorAll('form').length,
            0,
            'foreign-realm form clobbered by name="' +
              names[i] +
              '" is removed below the root'
          );
        }
      }
    );

    QUnit.test(
      'CVE-2026-49458: cross-window node is not mistaken for a string in IN_PLACE mode (GHSA-4w3q-35jp-p934)',
      function (assert) {
        // Where `Node` is an object (older WebKit), _isNode relied on
        // instanceof alone. A node from another window failed it, was
        // stringified to "[object HTMLDivElement]", IN_PLACE was switched
        // off and the node itself was never sanitized.
        if (typeof Symbol === 'undefined' || !Symbol.hasInstance) {
          assert.ok(true, 'SKIP: Symbol.hasInstance not available');
          return;
        }

        var NodeObject = { prototype: Object.create(window.Node.prototype) };
        Object.defineProperty(NodeObject, Symbol.hasInstance, {
          value: function () {
            return false;
          },
        });
        var realmPurify = createForeignRealmPurify(NodeObject);

        var root = document.createElement('div');
        root.setAttribute('onmouseover', 'alert(1)');
        root.innerHTML =
          '<img src="x" onerror="alert(2)"><script>alert(3)</script>';

        var clean = realmPurify.sanitize(root, { IN_PLACE: true });

        assert.equal(clean, root, 'the input node is returned, not a string');
        assert.equal(
          root.getAttribute('onmouseover'),
          null,
          'onmouseover on the cross-window root is stripped'
        );
        assert.equal(root.innerHTML, '<img src="x">', 'the node is sanitized');
      }
    );

    // -----------------------------------------------------------------------
    // CVE-2026-49978 (GHSA-rp9w-3fw7-7cwq) - attached shadow roots. The
    // NodeIterator does not enter shadow trees, so an open shadow root
    // attached to the IN_PLACE root or to any element below it, a clonable
    // shadow root copied by importNode() for node input, and a shadow root
    // nested inside <template>.content were reached by no walk at all and
    // their payload survived. A pre-pass now feeds every attached shadow root
    // (descending into <template>.content) into _sanitizeShadowDOM, and
    // _sanitizeShadowDOM walks the shadow root of every element it iterates.
    // The trees are built in an inert document, so no image request is made.
    // Engines without attachShadow skip these tests.
    // -----------------------------------------------------------------------
    var supportsShadowRoots = function () {
      var probe = document.createElement('div');
      try {
        probe.attachShadow({ mode: 'open' });
        return true;
      } catch (_) {
        return false;
      }
    };

    var supportsClonableShadowRoots = function () {
      var probe = document.createElement('div');
      try {
        probe.attachShadow({ mode: 'open', clonable: true });
      } catch (_) {
        return false;
      }

      // Engines predating clonable shadow roots accept the unknown dictionary
      // member, but do not copy the shadow root when cloning the host
      return Boolean(probe.cloneNode(true).shadowRoot);
    };

    // A document without a browsing context never loads images, so a
    // payload left unsanitized (e.g. the original of an imported node input)
    // can not fire its onerror handler and leak into the XSS tests
    var createInertDocument = function () {
      return document.implementation.createHTMLDocument('');
    };

    QUnit.test(
      'CVE-2026-49978: open shadow root of a <span> under the IN_PLACE root is sanitized',
      function (assert) {
        if (!supportsShadowRoots()) {
          assert.ok(true, 'SKIP: attachShadow not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          var root = doc.createElement('div');
          var span = doc.createElement('span');
          root.appendChild(span);
          span.attachShadow({ mode: 'open' }).innerHTML =
            '<img src=x onerror=alert(1)>';

          var clean = purify.sanitize(root, { IN_PLACE: true });

          assert.equal(clean, root, 'the input node is returned');
          var img = span.shadowRoot.querySelector('img');
          assert.ok(img, 'the allowed <img> is kept in the shadow root');
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror is stripped from the <img> in the shadow root'
          );
          assert.equal(
            span.shadowRoot.innerHTML,
            '<img src="x">',
            'the shadow root is sanitized'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: attached shadow roots in the main tree are sanitized in-place',
      function (assert) {
        if (!supportsShadowRoots()) {
          assert.ok(true, 'SKIP: attachShadow not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          var payload =
            '<img src=x onerror=alert(1)><script>alert(2)</script><b>ok</b>';
          // Shadow root on a descendant, nested shadow root, shadow root on
          // the root itself (upstream b4fdfe2e pre-pass)
          var root = doc.createElement('div');
          var host = doc.createElement('span');
          root.appendChild(host);
          var shadow = host.attachShadow({ mode: 'open' });
          shadow.innerHTML = payload + '<div></div>';
          shadow.lastChild.attachShadow({ mode: 'open' }).innerHTML = payload;
          root.attachShadow({ mode: 'open' }).innerHTML = payload;

          purify.sanitize(root, { IN_PLACE: true });

          var roots = [
            host.shadowRoot,
            host.shadowRoot.lastChild.shadowRoot,
            root.shadowRoot,
          ];
          for (var i = 0; i < roots.length; i++) {
            assert.equal(
              roots[i].querySelectorAll('script').length,
              0,
              'script removed from shadow root ' + i
            );
            var img = roots[i].querySelector('img');
            assert.ok(
              !img || img.getAttribute('onerror') === null,
              'onerror stripped in shadow root ' + i
            );
            assert.equal(
              roots[i].querySelectorAll('b').length,
              1,
              'allowed content kept in shadow root ' + i
            );
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: shadow root inside template.content is sanitized in-place',
      function (assert) {
        if (!supportsShadowRoots()) {
          assert.ok(true, 'SKIP: attachShadow not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          var tpl = doc.createElement('template');
          var host = doc.createElement('div');
          tpl.content.appendChild(host);
          host.attachShadow({ mode: 'open' }).innerHTML =
            '<img src=x onerror=alert(1)>';

          purify.sanitize(tpl, { IN_PLACE: true });

          // The shadow root's onerror attribute must be stripped.
          var shadowImg =
            tpl.content.firstChild &&
            tpl.content.firstChild.shadowRoot &&
            tpl.content.firstChild.shadowRoot.querySelector('img');
          if (shadowImg) {
            assert.equal(
              shadowImg.getAttribute('onerror'),
              null,
              'onerror inside shadow root inside template.content must be stripped'
            );
          } else {
            // The whole img may have been removed; also acceptable.
            assert.ok(
              true,
              '<img> removed entirely from shadow root inside template.content'
            );
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: clonable shadow root inside template.content does not survive stamping',
      function (assert) {
        if (!supportsClonableShadowRoots()) {
          assert.ok(
            true,
            'SKIP: clonable shadow roots not supported in this engine'
          );
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          var tpl = doc.createElement('template');
          var host = doc.createElement('div');
          tpl.content.appendChild(host);
          host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
            '<img src=x onerror=alert(1)>';

          purify.sanitize(tpl, { IN_PLACE: true });

          // The realistic exploitation path: clone the (now-sanitized)
          // template content into the live document. The cloned shadow
          // tree must not carry the onerror.
          var clone = tpl.content.cloneNode(true);
          var clonedImg =
            clone.firstChild &&
            clone.firstChild.shadowRoot &&
            clone.firstChild.shadowRoot.querySelector('img');
          if (clonedImg) {
            assert.equal(
              clonedImg.getAttribute('onerror'),
              null,
              'onerror inside cloned-stamped shadow root must be stripped'
            );
          } else {
            assert.ok(true, '<img> removed entirely after stamping');
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: nested templates: outer.content > inner.content > shadow root',
      function (assert) {
        if (!supportsShadowRoots()) {
          assert.ok(true, 'SKIP: attachShadow not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // Two <template> elements nested by content. The innermost
          // host inside the inner template's content carries the
          // malicious shadow root. Reaches the host only via repeated
          // recursion into template.content.
          var outer = doc.createElement('template');
          var inner = doc.createElement('template');
          var host = doc.createElement('div');
          inner.content.appendChild(host);
          outer.content.appendChild(inner);
          host.attachShadow({ mode: 'open' }).innerHTML =
            '<img src=x onerror=alert(1)>';

          purify.sanitize(outer, { IN_PLACE: true });

          var sr =
            outer.content.firstChild &&
            outer.content.firstChild.content &&
            outer.content.firstChild.content.firstChild &&
            outer.content.firstChild.content.firstChild.shadowRoot;
          var img = sr && sr.querySelector('img');
          if (img) {
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror in shadow root inside nested template content must be stripped'
            );
          } else {
            assert.ok(true, '<img> removed entirely');
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: wrapper element > template > shadow root: walked via descent',
      function (assert) {
        if (!supportsShadowRoots()) {
          assert.ok(true, 'SKIP: attachShadow not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // A regular <div> as the IN_PLACE root, containing a template,
          // whose content holds a shadow host. The walk must descend
          // through the wrapper, find the template, recurse into
          // template.content, and walk the host's shadow root.
          var root = doc.createElement('div');
          var tpl = doc.createElement('template');
          var host = doc.createElement('div');
          tpl.content.appendChild(host);
          root.appendChild(tpl);
          host.attachShadow({ mode: 'open' }).innerHTML =
            '<img src=x onerror=alert(1)>';

          purify.sanitize(root, { IN_PLACE: true });

          var sr =
            root.firstChild &&
            root.firstChild.content &&
            root.firstChild.content.firstChild &&
            root.firstChild.content.firstChild.shadowRoot;
          var img = sr && sr.querySelector('img');
          if (img) {
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror in shadow root inside template inside wrapper must be stripped'
            );
          } else {
            assert.ok(true, '<img> removed entirely');
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: <template> nested inside a shadow root inside template.content is walked',
      function (assert) {
        if (!supportsShadowRoots()) {
          assert.ok(true, 'SKIP: attachShadow not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // Template.content > host > shadow root > template > img. The
          // walk alternates between shadow-root descent and
          // template-content recursion.
          var outer = doc.createElement('template');
          var host = doc.createElement('div');
          outer.content.appendChild(host);
          var sr = host.attachShadow({ mode: 'open' });
          var inner = doc.createElement('template');
          inner.innerHTML = '<img src=x onerror=alert(1)>';
          sr.appendChild(inner);

          purify.sanitize(outer, { IN_PLACE: true });

          var innerTpl =
            outer.content.firstChild &&
            outer.content.firstChild.shadowRoot &&
            outer.content.firstChild.shadowRoot.querySelector('template');
          var img = innerTpl && innerTpl.content.querySelector('img');
          if (img) {
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror inside <template>.content inside shadow root must be stripped'
            );
          } else {
            assert.ok(true, '<img> removed entirely');
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: template.content > shadow root > template > shadow root: alternating descent',
      function (assert) {
        if (!supportsShadowRoots()) {
          assert.ok(true, 'SKIP: attachShadow not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // Outer host with shadow root inside template content, whose
          // shadow contains a <template>, whose content contains an inner
          // host with its own shadow root carrying the payload.
          var tpl = doc.createElement('template');
          var outerHost = doc.createElement('div');
          tpl.content.appendChild(outerHost);
          var outerSr = outerHost.attachShadow({ mode: 'open' });
          var innerTpl = doc.createElement('template');
          outerSr.appendChild(innerTpl);
          var innerHost = doc.createElement('div');
          innerTpl.content.appendChild(innerHost);
          innerHost.attachShadow({ mode: 'open' }).innerHTML =
            '<img src=x onerror=alert(1)>';

          purify.sanitize(tpl, { IN_PLACE: true });

          var outerShadow =
            tpl.content.firstChild && tpl.content.firstChild.shadowRoot;
          var innerSr =
            outerShadow &&
            outerShadow.firstChild &&
            outerShadow.firstChild.content &&
            outerShadow.firstChild.content.firstChild &&
            outerShadow.firstChild.content.firstChild.shadowRoot;
          var img = innerSr && innerSr.querySelector('img');
          if (img) {
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror in deep shadow > template > shadow chain must be stripped'
            );
          } else {
            assert.ok(true, '<img> removed entirely');
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: shadow root nested inside a shadow root inside template.content is walked',
      function (assert) {
        if (!supportsShadowRoots()) {
          assert.ok(true, 'SKIP: attachShadow not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // Template.content > host > shadow root > host > shadow root
          var tpl = doc.createElement('template');
          var outerHost = doc.createElement('div');
          tpl.content.appendChild(outerHost);
          var outerSr = outerHost.attachShadow({ mode: 'open' });
          outerSr.innerHTML = '<b>ok</b><span></span>';
          outerSr.lastChild.attachShadow({ mode: 'open' }).innerHTML =
            '<p>ok</p><img src=x onerror=alert(1)><script>alert(2)</script>';

          purify.sanitize(tpl, { IN_PLACE: true });

          var shadow = tpl.content.firstChild.shadowRoot;
          assert.equal(
            shadow.innerHTML,
            '<b>ok</b><span></span>',
            'benign content of the outer shadow root is kept'
          );
          assert.equal(
            shadow.lastChild.shadowRoot.innerHTML,
            '<p>ok</p><img src="x">',
            'payload of the inner shadow root is sanitized'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: clonable shadow root in nested template survives stamping unscathed',
      function (assert) {
        if (!supportsClonableShadowRoots()) {
          assert.ok(true, 'SKIP: clonable shadow roots not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // End-to-end version of the deeper-nesting case: clonable
          // shadow root inside nested template content, then stamp the
          // outer template into the live document. The cloned tree
          // must not carry the original onerror.
          var outer = doc.createElement('template');
          var inner = doc.createElement('template');
          var host = doc.createElement('div');
          inner.content.appendChild(host);
          outer.content.appendChild(inner);
          host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
            '<img src=x onerror=alert(1)>';

          purify.sanitize(outer, { IN_PLACE: true });

          // Stamp the outer template into the live document.
          var stamped = outer.content.cloneNode(true);
          var stampedSr =
            stamped.firstChild &&
            stamped.firstChild.content &&
            stamped.firstChild.content.firstChild &&
            stamped.firstChild.content.firstChild.shadowRoot;
          var stampedImg = stampedSr && stampedSr.querySelector('img');
          if (stampedImg) {
            assert.equal(
              stampedImg.getAttribute('onerror'),
              null,
              'stamped img onerror stripped after deep-nested sanitize'
            );
          } else {
            assert.ok(true, '<img> removed entirely after stamping');
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: clonable shadow root inside template.content of a node input is sanitized',
      function (assert) {
        if (!supportsClonableShadowRoots()) {
          assert.ok(true, 'SKIP: clonable shadow roots not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // Without IN_PLACE the node is imported (cloned) into the
          // sanitization document, which copies the clonable shadow root.
          var root = doc.createElement('div');
          var tpl = doc.createElement('template');
          var host = doc.createElement('div');
          tpl.content.appendChild(host);
          root.appendChild(tpl);
          host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
            '<img src=x onerror=alert(1)>';

          var clean = purify.sanitize(root, { RETURN_DOM: true });

          var cleanTpl = clean.querySelector('template');
          var sr =
            cleanTpl &&
            cleanTpl.content.firstChild &&
            cleanTpl.content.firstChild.shadowRoot;
          var img = sr && sr.querySelector('img');
          if (img) {
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror in the copied shadow root must be stripped'
            );
          } else {
            assert.ok(true, '<img> removed entirely');
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: clonable shadow root copied by importNode() is sanitized for RETURN_DOM and RETURN_DOM_FRAGMENT',
      function (assert) {
        if (!supportsClonableShadowRoots()) {
          assert.ok(true, 'SKIP: clonable shadow roots not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // Node input without IN_PLACE is deep-cloned by importNode(),
          // which copies a clonable shadow root along with its host
          // (upstream b4fdfe2e).
          var build = function () {
            var root = doc.createElement('div');
            var host = doc.createElement('span');
            root.appendChild(host);
            host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
              '<img src=x onerror=alert(1)><script>alert(2)</script>';
            return root;
          };

          var configs = [{ RETURN_DOM: true }, { RETURN_DOM_FRAGMENT: true }];
          for (var i = 0; i < configs.length; i++) {
            var clean = purify.sanitize(build(), configs[i]);
            var host = clean.querySelector('span');
            if (!host || !host.shadowRoot) {
              assert.ok(true, 'SKIP: importNode() did not copy the shadow root');
              continue;
            }

            assert.equal(
              host.shadowRoot.innerHTML,
              '<img src="x">',
              'the copied shadow root is sanitized (' +
                Object.keys(configs[i])[0] +
                ')'
            );
          }
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: clonable shadow root of a DocumentFragment node input is sanitized',
      function (assert) {
        if (!supportsClonableShadowRoots()) {
          assert.ok(true, 'SKIP: clonable shadow roots not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // The imported fragment is emptied into the sanitization body by
          // appendChild(), so the walk has to start from the body
          var fragment = doc.createDocumentFragment();
          var host = doc.createElement('div');
          fragment.appendChild(host);
          host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
            '<img src=x onerror=alert(1)>';

          var clean = purify.sanitize(fragment, { RETURN_DOM: true });

          var cleanHost = clean.querySelector('div');
          if (!cleanHost || !cleanHost.shadowRoot) {
            assert.ok(true, 'SKIP: importNode() did not copy the shadow root');
            return;
          }

          assert.equal(
            cleanHost.shadowRoot.innerHTML,
            '<img src="x">',
            'the copied shadow root is sanitized'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: a clobbering form descendant does not hide shadow roots from the walk',
      function (assert) {
        if (!supportsShadowRoots()) {
          assert.ok(true, 'SKIP: attachShadow not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // <input name="childNodes"> shadows form.childNodes, a walk using
          // direct reads would stop at the form and miss the host below it
          var root = doc.createElement('div');
          var form = doc.createElement('form');
          var input = doc.createElement('input');
          input.setAttribute('name', 'childNodes');
          var host = doc.createElement('span');
          form.appendChild(input);
          form.appendChild(host);
          root.appendChild(form);
          host.attachShadow({ mode: 'open' }).innerHTML =
            '<img src=x onerror=alert(1)>';

          purify.sanitize(root, { IN_PLACE: true });

          assert.equal(
            host.shadowRoot.innerHTML,
            '<img src="x">',
            'the shadow root below the clobbered form is sanitized'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-49978: each nested shadow root is sanitized once per call',
      function (assert) {
        if (!supportsShadowRoots()) {
          assert.ok(true, 'SKIP: attachShadow not supported');
          return;
        }

        withFreshPurify(function (purify) {
          var doc = createInertDocument();
          // The pre-pass and the shadowRoot check in _sanitizeShadowDOM both
          // reach a nested shadow root. Without deduplication a shadow root
          // nested n levels deep is sanitized 2^n times.
          var depth = 16;
          var root = doc.createElement('div');
          var parent = root;
          var innermost = null;
          for (var i = 0; i < depth; i++) {
            var host = doc.createElement('div');
            parent.appendChild(host);
            innermost = host.attachShadow({ mode: 'open' });
            parent = innermost;
          }

          innermost.innerHTML = '<img src=x onerror=alert(1)>';

          var calls = 0;
          purify.addHook('beforeSanitizeShadowDOM', function () {
            calls++;
          });
          purify.sanitize(root, { IN_PLACE: true });

          assert.equal(calls, depth, 'every shadow root is sanitized once');
          assert.equal(
            innermost.innerHTML,
            '<img src="x">',
            'the innermost shadow root is sanitized'
          );
        });
      }
    );

    // -----------------------------------------------------------------------
    // CVE-2026-65901 (GHSA-x4vx-rjvf-j5p4): a live node handed in with
    // IN_PLACE can define an own nodeName. The allow/forbid decisions trusted
    // that instance-visible property, so a real <script> claiming to be a
    // "DIV" was kept and ran once the sanitized tree was inserted into the
    // document, and an <a> claiming to be an "IMG" kept a data: URI. The name
    // is now read through the cached Node.prototype getter, and a node whose
    // own nodeName diverges from it is removed like any other clobbered node.
    // -----------------------------------------------------------------------
    var X4VX_DATA_URI =
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==';
    var spoofNodeName = function (node, name) {
      Object.defineProperty(node, 'nodeName', {
        value: name,
        configurable: true,
      });
      return node;
    };
    var hasDataHref = function (node) {
      return /^\s*data:/i.test(node.getAttribute('href') || '');
    };

    QUnit.test(
      'CVE-2026-65901: IN_PLACE removes a <script> child spoofing nodeName as DIV',
      function (assert) {
        withFreshPurify(function (purify) {
          var host = document.createElement('div');
          var benign = document.createElement('p');
          benign.appendChild(document.createTextNode('ok'));
          host.appendChild(benign);
          var script = document.createElement('script');
          script.textContent = 'window.__x4vx_script = 1';
          host.appendChild(spoofNodeName(script, 'DIV'));

          var clean = purify.sanitize(host, { IN_PLACE: true });

          assert.strictEqual(clean, host, 'the root node itself is returned');
          assert.notEqual(
            script.parentNode,
            host,
            '<script> spoofing nodeName as DIV is removed'
          );
          assert.equal(
            host.childNodes.length,
            1,
            'only the benign child is left'
          );
          assert.strictEqual(host.firstChild, benign, 'benign <p> is kept');
        });
      }
    );

    QUnit.test(
      'CVE-2026-65901: IN_PLACE does not keep a data: href on an <a> spoofing nodeName as IMG',
      function (assert) {
        withFreshPurify(function (purify) {
          var host = document.createElement('div');
          var link = document.createElement('a');
          link.setAttribute('href', X4VX_DATA_URI);
          link.appendChild(document.createTextNode('click'));
          host.appendChild(spoofNodeName(link, 'IMG'));

          purify.sanitize(host, { IN_PLACE: true });

          assert.ok(
            link.parentNode !== host || !hasDataHref(link),
            '<a> spoofing nodeName as IMG is removed or loses its data: href'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65901: a nodeName getter switching to IMG after the first reads can not keep a data: href',
      function (assert) {
        withFreshPurify(function (purify) {
          var host = document.createElement('div');
          var link = document.createElement('a');
          link.setAttribute('href', X4VX_DATA_URI);
          link.appendChild(document.createTextNode('click'));
          host.appendChild(link);
          // Consistent while the node is checked for clobbering and its tag
          // name is looked up, spoofed for the attribute checks after
          var reads = 0;
          Object.defineProperty(link, 'nodeName', {
            get: function () {
              reads++;
              return reads <= 2 ? 'A' : 'IMG';
            },
            configurable: true,
          });

          purify.sanitize(host, { IN_PLACE: true });

          assert.ok(
            link.parentNode !== host || !hasDataHref(link),
            'data: href is not kept by a nodeName that turns into IMG'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65901: IN_PLACE root spoofing nodeName is refused',
      function (assert) {
        withFreshPurify(function (purify) {
          var root = document.createElement('script');
          root.textContent = 'window.__x4vx_root = 1';
          spoofNodeName(root, 'DIV');

          var message = null;
          try {
            purify.sanitize(root, { IN_PLACE: true });
          } catch (error) {
            message = String(error && error.message);
          }

          // The root pre-check reads the name through the cached getter, so
          // the real <script> is refused as a forbidden root
          assert.ok(
            message !== null && /forbidden|clobbered/.test(message),
            'spoofed IN_PLACE root must throw, got: ' + message
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65901: IN_PLACE root <a> spoofing nodeName as IMG keeps no data: href',
      function (assert) {
        withFreshPurify(function (purify) {
          var root = document.createElement('a');
          root.setAttribute('href', X4VX_DATA_URI);
          root.appendChild(document.createTextNode('click'));
          spoofNodeName(root, 'IMG');

          var message = null;
          try {
            purify.sanitize(root, { IN_PLACE: true });
          } catch (error) {
            message = String(error && error.message);
          }

          assert.ok(
            (message !== null && /clobbered/.test(message)) ||
              !hasDataHref(root),
            'spoofed <a> root is refused or loses its data: href, got: ' +
              message
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65901: IN_PLACE removes an adopted <script> spoofing nodeName as DIV',
      function (assert) {
        if (
          !document.implementation ||
          typeof document.implementation.createHTMLDocument !== 'function' ||
          typeof document.adoptNode !== 'function'
        ) {
          assert.ok(true, 'SKIP: no createHTMLDocument / adoptNode');
          return;
        }

        withFreshPurify(function (purify) {
          // Build the hostile subtree in another document, then adopt it into
          // this one before sanitizing it in place
          var source = document.implementation.createHTMLDocument('');
          var host = source.createElement('div');
          var script = source.createElement('script');
          script.textContent = 'window.__x4vx_adopted = 1';
          host.appendChild(spoofNodeName(script, 'DIV'));
          var link = source.createElement('a');
          link.setAttribute('href', X4VX_DATA_URI);
          host.appendChild(spoofNodeName(link, 'IMG'));
          host = document.adoptNode(host);

          purify.sanitize(host, { IN_PLACE: true });

          assert.notEqual(
            script.parentNode,
            host,
            'adopted <script> spoofing nodeName as DIV is removed'
          );
          assert.ok(
            link.parentNode !== host || !hasDataHref(link),
            'adopted <a> spoofing nodeName as IMG keeps no data: href'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-65901: IN_PLACE removes a foreign-realm <script> spoofing nodeName as DIV',
      function (assert) {
        var realmPurify = createForeignRealmPurify();
        var host = document.createElement('div');
        var script = document.createElement('script');
        script.textContent = 'window.__x4vx_foreign = 1';
        host.appendChild(spoofNodeName(script, 'DIV'));
        var link = document.createElement('a');
        link.setAttribute('href', X4VX_DATA_URI);
        host.appendChild(spoofNodeName(link, 'IMG'));

        realmPurify.sanitize(host, { IN_PLACE: true });

        assert.notEqual(
          script.parentNode,
          host,
          'foreign realm: <script> spoofing nodeName as DIV is removed'
        );
        assert.ok(
          link.parentNode !== host || !hasDataHref(link),
          'foreign realm: <a> spoofing nodeName as IMG keeps no data: href'
        );
      }
    );

    // -----------------------------------------------------------------------
    // CVE-2026-75838 (GHSA-55q2-fjhq-7xh7, GHSA-p98j-92pf-mc4p): a hook that
    // detaches a node via node.remove() (the documented removal pattern)
    // takes the subtree out of the tree before the walker reaches its
    // descendants - so they are never visited, and hook-detached nodes are
    // not recorded in DOMPurify.removed. On the IN_PLACE path the caller
    // built that subtree in the live document, so a descendant that was
    // already loading kept its queued on* handler and fired in page scope
    // after sanitize returned, even though the returned tree was clean.
    // Covers every per-node hook site that can detach the node:
    // beforeSanitizeElements, uponSanitizeElement, afterSanitizeElements,
    // beforeSanitizeAttributes and afterSanitizeAttributes (the after* hooks
    // are the documented place for node.remove() policies).
    // -----------------------------------------------------------------------
    var detachNode = function (node) {
      if (typeof node.remove === 'function') {
        node.remove();
      } else {
        node.parentNode.removeChild(node);
      }
    };

    var detachingHooks = [
      'uponSanitizeElement',
      'beforeSanitizeElements',
      'afterSanitizeElements',
      'beforeSanitizeAttributes',
      'afterSanitizeAttributes',
    ];

    detachingHooks.forEach(function (hook) {
      QUnit.test(
        'CVE-2026-75838: IN_PLACE: ' +
          hook +
          ' node.remove() neutralizes the detached subtree',
        function (assert) {
          var root = document.createElement('div');
          root.innerHTML =
            '<section><img id="tail" onerror="alert(1)"></section>' +
            '<div>safe</div>';
          var tail = root.querySelector('#tail');

          DOMPurify.addHook(hook, function (node) {
            if (node.nodeName === 'SECTION') {
              detachNode(node);
            }
          });

          try {
            var ret = DOMPurify.sanitize(root, { IN_PLACE: true });

            assert.equal(ret, root, 'returns the same in-place node');
            assert.notOk(
              ret.querySelector('section, #tail'),
              'detached subtree is absent from the returned tree'
            );
            assert.strictEqual(
              tail.getAttribute('onerror'),
              null,
              'on* handler stripped from the hook-detached descendant'
            );

            // App-side store-and-rerender must expose no executable sink.
            var probe = document.createElement('div');
            probe.innerHTML = ret.outerHTML + tail.outerHTML;
            assert.notOk(
              probe.querySelector('[onerror],[onload],script'),
              'no executable sink survives serialize/reparse: ' +
                probe.innerHTML
            );
          } finally {
            DOMPurify.removeHook(hook);
          }
        }
      );

      QUnit.test(
        'CVE-2026-75838: IN_PLACE: ' +
          hook +
          ' node.remove() leaves no loading handler to fire after sanitize',
        function (assert) {
          var done = assert.async();
          var sentinel = '__cve75838_' + hook;
          window[sentinel] = 0;

          withFreshPurify(function (purify) {
            // The <img> starts loading (and fails) as soon as the markup is
            // parsed in the live document, before sanitize runs; its error
            // event is queued and fires after sanitize returns.
            var root = document.createElement('div');
            root.innerHTML =
              '<section><p><img src="data:,x" onerror="window.' +
              sentinel +
              ' = 1"></p></section><div>safe</div>';

            purify.addHook(hook, function (node) {
              if (node.nodeName === 'SECTION') {
                detachNode(node);
              }
            });

            purify.sanitize(root, { IN_PLACE: true });

            assert.notOk(
              root.querySelector('section, img'),
              'detached subtree is absent from the returned tree'
            );
          });

          setTimeout(function () {
            assert.strictEqual(
              window[sentinel],
              0,
              'handler of the hook-detached <img> must not fire in page scope'
            );
            try {
              delete window[sentinel];
            } catch (_) {
              window[sentinel] = undefined;
            }

            done();
          }, 500);
        }
      );
    });

    // Every way a hook can take a node out of the IN_PLACE tree (remove(),
    // removeChild(), replaceChild() with a safe stand-in) leaves no handler
    // anywhere in the deep detached subtree, while allow-listed attributes on
    // it are kept and the kept part of the tree is still sanitized.
    var hasEventHandler = function (element) {
      for (var i = 0; i < element.attributes.length; i++) {
        if (/^on/i.test(element.attributes[i].name)) {
          return true;
        }
      }

      return false;
    };

    [
      ['remove()', detachNode],
      [
        'removeChild()',
        function (node) {
          node.parentNode.removeChild(node);
        },
      ],
      [
        'replaceChild()',
        function (node) {
          node.parentNode.replaceChild(
            node.ownerDocument.createElement('span'),
            node
          );
        },
      ],
    ].forEach(function (detachCase) {
      detachingHooks.forEach(function (hook) {
        QUnit.test(
          'CVE-2026-75838: IN_PLACE: ' +
            hook +
            ' detaching via ' +
            detachCase[0] +
            ' neutralizes every descendant of the detached subtree',
          function (assert) {
            withFreshPurify(function (purify) {
              var root = document.createElement('div');
              root.innerHTML =
                '<article onmouseover="alert(1)"><div title="keep">' +
                '<img id="deep" onerror="alert(2)" onload="alert(3)">' +
                '<svg><g onclick="alert(4)"></g></svg>' +
                '<video><source onerror="alert(5)"></video>' +
                '<p><b><i><img onerror="alert(6)"></i></b></p>' +
                '</div></article>' +
                '<p onclick="alert(7)">kept</p>';
              var detached = root.querySelector('article');
              var keepTitle = root.querySelector('[title]');
              var kept = root.querySelector('p[onclick]');

              purify.addHook(hook, function (node) {
                if (node.nodeName === 'ARTICLE') {
                  detachCase[1](node);
                }
              });

              var ret = purify.sanitize(root, { IN_PLACE: true });

              assert.strictEqual(ret, root, 'returns the same in-place node');
              assert.notOk(
                ret.querySelector('article'),
                'detached subtree is absent from the returned tree'
              );

              var offenders = [];
              var elements = [detached].concat(
                Array.prototype.slice.call(detached.querySelectorAll('*'))
              );
              for (var i = 0; i < elements.length; i++) {
                if (hasEventHandler(elements[i])) {
                  offenders.push(elements[i].nodeName);
                }
              }

              assert.equal(
                offenders.join(','),
                '',
                'no on* handler survives in the hook-detached subtree'
              );
              assert.equal(
                keepTitle.getAttribute('title'),
                'keep',
                'allow-listed attributes on the detached subtree are kept'
              );
              assert.strictEqual(
                kept.getAttribute('onclick'),
                null,
                'the kept part of the tree is still sanitized'
              );
              assert.notOk(
                /\son\w+=/i.test(ret.outerHTML + detached.outerHTML),
                'no handler survives serialization: ' +
                  ret.outerHTML +
                  detached.outerHTML
              );
            });
          }
        );
      });
    });

    QUnit.test(
      'CVE-2026-75838: IN_PLACE: neutralization only strips non-allow-listed attributes',
      function (assert) {
        withFreshPurify(function (purify) {
          var root = document.createElement('div');
          root.innerHTML =
            '<section title="t"><a id="tail" href="https://example.com/" ' +
            'class="c" onclick="alert(1)">x</a>' +
            '<a id="js" href="javascript:alert(2)">y</a></section>' +
            '<p class="kept">safe</p>';
          var tail = root.querySelector('#tail');
          var js = root.querySelector('#js');

          purify.addHook('uponSanitizeElement', function (node) {
            if (node.nodeName === 'SECTION') {
              detachNode(node);
            }
          });

          purify.sanitize(root, { IN_PLACE: true });

          assert.strictEqual(
            tail.getAttribute('onclick'),
            null,
            'on* handler stripped from the detached descendant'
          );
          assert.strictEqual(
            js.getAttribute('href'),
            null,
            'script URI stripped from the detached descendant'
          );
          assert.strictEqual(
            tail.getAttribute('href'),
            'https://example.com/',
            'allow-listed href is kept on the detached descendant'
          );
          assert.strictEqual(tail.getAttribute('class'), 'c');
          assert.equal(
            root.innerHTML,
            '<p class="kept">safe</p>',
            'the attached remainder is sanitized as usual'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-75838: IN_PLACE: a hook detaching a node inside an attached shadow root neutralizes it',
      function (assert) {
        var doc = document.implementation.createHTMLDocument('');
        var root = doc.createElement('div');
        if (typeof root.attachShadow !== 'function') {
          assert.ok(true, 'Shadow DOM is not supported, nothing to test');
          return;
        }

        withFreshPurify(function (purify) {
          var host = doc.createElement('div');
          root.appendChild(host);
          var shadowRoot = host.attachShadow({ mode: 'open' });
          shadowRoot.innerHTML =
            '<section><img id="tail" onerror="alert(1)"></section>' +
            '<img id="kept" onerror="alert(2)">';
          var tail = shadowRoot.querySelector('#tail');
          var kept = shadowRoot.querySelector('#kept');

          purify.addHook('uponSanitizeElement', function (node) {
            if (node.nodeName === 'SECTION') {
              detachNode(node);
            }
          });

          purify.sanitize(root, { IN_PLACE: true });

          assert.notOk(
            shadowRoot.querySelector('section'),
            'detached subtree is absent from the shadow root'
          );
          assert.strictEqual(
            tail.getAttribute('onerror'),
            null,
            'on* handler stripped from the hook-detached shadow descendant'
          );
          assert.strictEqual(
            kept.getAttribute('onerror'),
            null,
            'the kept part of the shadow root is still sanitized'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-75838: IN_PLACE: a parent-less root is still sanitized while hooks are registered',
      function (assert) {
        withFreshPurify(function (purify) {
          // The walk root is exempt from the hook-detach handling: a
          // detached IN_PLACE root is legitimate input and must be sanitized.
          var root = document.createElement('div');
          root.setAttribute('onmouseover', 'alert(1)');
          root.innerHTML =
            '<section><img onerror="alert(2)"></section>' +
            '<img id="kept" onerror="alert(3)">';
          var seen = [];
          purify.addHook('beforeSanitizeElements', function (node) {
            seen.push(node.nodeName);
          });
          purify.addHook('uponSanitizeElement', function (node) {
            if (node.nodeName === 'SECTION') {
              detachNode(node);
            }
          });

          var ret = purify.sanitize(root, { IN_PLACE: true });

          assert.strictEqual(ret, root, 'returns the same in-place node');
          assert.strictEqual(
            root.getAttribute('onmouseover'),
            null,
            'on* handler stripped from the parent-less root'
          );
          assert.strictEqual(
            root.querySelector('#kept').getAttribute('onerror'),
            null,
            'on* handler stripped from the kept sibling'
          );
          assert.equal(seen[0], 'DIV', 'the root itself was walked');
        });
      }
    );

    QUnit.test(
      'CVE-2026-75838: IN_PLACE: a parent-less root is fully attribute-sanitized while every detach-checked hook is registered',
      function (assert) {
        withFreshPurify(function (purify) {
          // The root is exempt at the attribute hook sites too: it must go
          // through the full attribute pass (URI checks included), not only
          // the allowlist strip used for discarded subtrees.
          var root = document.createElement('a');
          root.setAttribute('href', 'javascript:alert(1)');
          root.setAttribute('onclick', 'alert(2)');
          root.innerHTML = '<img id="kept" onerror="alert(3)">';
          var seen = [];
          detachingHooks.forEach(function (hook) {
            purify.addHook(hook, function (node) {
              if (node === root) {
                seen.push(hook);
              }
            });
          });

          var ret = purify.sanitize(root, { IN_PLACE: true });

          assert.strictEqual(ret, root, 'returns the same in-place node');
          assert.strictEqual(
            root.getAttribute('href'),
            null,
            'unsafe URI stripped from the parent-less root'
          );
          assert.strictEqual(
            root.getAttribute('onclick'),
            null,
            'on* handler stripped from the parent-less root'
          );
          assert.strictEqual(
            root.querySelector('#kept').getAttribute('onerror'),
            null,
            'on* handler stripped from the kept child'
          );
          assert.equal(
            seen.join(','),
            'beforeSanitizeElements,uponSanitizeElement,afterSanitizeElements,' +
              'beforeSanitizeAttributes,afterSanitizeAttributes',
            'every hook ran for the root'
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-75838: IN_PLACE: root detached by a hook is still fully sanitized',
      function (assert) {
        withFreshPurify(function (purify) {
          // The walk root itself is exempt: a hook that detaches the
          // IN_PLACE root does not stop the walk from sanitizing it.
          var host = document.createElement('div');
          var root = document.createElement('div');
          root.innerHTML = '<img onerror="alert(1)"><b>ok</b>';
          host.appendChild(root);

          purify.addHook('beforeSanitizeElements', function (node) {
            if (node === root) {
              detachNode(node);
            }
          });

          var ret = purify.sanitize(root, { IN_PLACE: true });

          assert.equal(ret, root, 'returns the same in-place node');
          assert.equal(root.innerHTML, '<img><b>ok</b>');
        });
      }
    );

    QUnit.test(
      'CVE-2026-75838: hook-detached nodes do not change string and DOM sanitization output',
      function (assert) {
        detachingHooks.forEach(function (hook) {
          withFreshPurify(function (purify) {
            purify.addHook(hook, function (node) {
              if (node.nodeName === 'SECTION') {
                detachNode(node);
              }
            });

            assert.equal(
              purify.sanitize(
                '<section><img src=x onerror=alert(1)></section><p>ok</p>'
              ),
              '<p>ok</p>',
              hook + ': string path drops the hook-detached subtree'
            );

            var node = document.createElement('div');
            node.innerHTML =
              '<section><img onerror=alert(1)></section><p>ok</p>';
            assert.equal(
              purify.sanitize(node, { RETURN_DOM: true }).innerHTML,
              '<div><p>ok</p></div>',
              hook + ': DOM path drops the hook-detached subtree'
            );
          });
        });
      }
    );

    // -----------------------------------------------------------------------
    // CVE-2026-109345 (GHSA-6688-9rhm-gjv2): an IN_PLACE root that the walk
    // itself force-removes (a rawtext <style> root killed by the mXSS check,
    // a fallback-tag root, a root a hook disallows, ...) used to be handed
    // back to the caller, and KEEP_CONTENT hoisted the content of a removed
    // root into the caller's live parent, outside the walk, where it was
    // never sanitized. For a rawtext root whose text already carries its own
    // end tag the literal serialization ("<style></style><img ...></style>")
    // re-opens markup on a plain HTML reparse. sanitize() must refuse such a
    // root instead of returning it.
    // -----------------------------------------------------------------------
    QUnit.test(
      'CVE-2026-109345: a removed attached IN_PLACE root does not hoist its content into the live parent',
      function (assert) {
        // KEEP_CONTENT re-inserts a removed element's content after it. For
        // the IN_PLACE root that lands in the caller's parent, outside the
        // walk, where it would never be sanitized. This version refuses a
        // disallowed root such as <x-widget> already at the IN_PLACE entry,
        // before the walk starts, and leaves the caller's root untouched.
        var doc = createInertDocument();
        var parent = doc.createElement('div');
        var root = doc.createElement('x-widget');
        root.innerHTML = '<img src=x onerror=alert(1)><b>t</b>';
        parent.appendChild(root);
        assert.throws(function () {
          DOMPurify.sanitize(root, { IN_PLACE: true });
        }, /refusing to sanitize in place|cannot be sanitized in-place/);
        var hoisted = 0;
        for (var i = 0; i < parent.childNodes.length; i++) {
          if (parent.childNodes[i] !== root) {
            hoisted++;
          }
        }

        assert.equal(
          hoisted,
          0,
          'no unsanitized markup hoisted into the live parent: ' +
            parent.innerHTML
        );
      }
    );

    QUnit.test(
      'CVE-2026-109345: a root disallowed by a hook does not hoist its content into the live parent',
      function (assert) {
        withFreshPurify(function (purify) {
          // The root passes the IN_PLACE entry check, then a hook takes it
          // off the allow-list, so the walk removes it with KEEP_CONTENT.
          // Built in an inert document so an unpatched run can not fire the
          // hoisted <img> handler in page scope.
          var doc = createInertDocument();
          var parent = doc.createElement('div');
          var root = doc.createElement('div');
          root.setAttribute('onclick', 'alert(1)');
          root.innerHTML = '<img src=x onerror=alert(2)><b>t</b>';
          parent.appendChild(root);

          purify.addHook('uponSanitizeElement', function (node, data) {
            if (node === root) {
              delete data.allowedTags[data.tagName];
            }
          });

          assert.throws(
            function () {
              purify.sanitize(root, { IN_PLACE: true });
            },
            /refusing to sanitize in place/,
            'the removed root is not returned'
          );
          assert.equal(
            parent.getElementsByTagName('img').length,
            0,
            'no unsanitized markup hoisted into the live parent'
          );
          assert.equal(
            parent.querySelectorAll('[onerror],[onclick]').length,
            0,
            'no handler in the live parent: ' + parent.innerHTML
          );
          assert.equal(
            root.getAttribute('onclick'),
            null,
            'the on* handler on the refused root is cancelled'
          );
          assert.equal(
            root.querySelectorAll('[onerror],[onclick]').length,
            0,
            'no handler left in the refused subtree: ' + root.innerHTML
          );
        });
      }
    );

    QUnit.test(
      'CVE-2026-109345: throws instead of returning a force-removed rawtext root (mXSS reparse)',
      function (assert) {
        // A <style> passed as the IN_PLACE root whose text content already
        // carries its own end tag is force-removed by the mXSS check: its
        // literal serialization ("</style><img ...>") re-opens markup on an
        // HTML reparse. The detached root must not be handed back to the
        // caller. Fail closed - assert the return contract, not merely a
        // scrubbed textContent, so a future refactor cannot pass by
        // defanging text while still returning.
        var dirty = document.createElement('style');
        dirty.setAttribute('onclick', 'alert(1)');
        dirty.textContent = '</style><img src=x onerror=alert(1)>';
        document.body.appendChild(dirty);

        assert.throws(
          function () {
            DOMPurify.sanitize(dirty, { IN_PLACE: true });
          },
          /refusing to sanitize in place/,
          'force-removed rawtext root is not returned'
        );
        assert.ok(
          DOMPurify.removed.some(function (entry) {
            return entry.element === dirty;
          }),
          'root was recorded as removed during the aborted call'
        );
        assert.equal(
          dirty.getAttribute('onclick'),
          null,
          'the on* handler on the refused root is cancelled'
        );

        if (dirty.parentNode) {
          dirty.parentNode.removeChild(dirty);
        }

        window.xssed = false;
      }
    );

    QUnit.test(
      'CVE-2026-109345: still returns the root when a rawtext CHILD (not the root) is removed',
      function (assert) {
        // The fail-closed guard must fire ONLY when the ROOT itself is
        // force-removed. A dangerous rawtext child is detached from the
        // returned root as usual; the root remains safe to return, so the
        // guard must not over-trigger on ordinary child removals.
        var dirty = document.createElement('div');
        dirty.innerHTML = '<span>ok</span>';
        var style = document.createElement('style');
        style.textContent = '</style><img src=x onerror=alert(1)>';
        dirty.appendChild(style);
        document.body.appendChild(dirty);

        var clean = DOMPurify.sanitize(dirty, { IN_PLACE: true });
        assert.equal(clean, dirty, 'returns the input root');
        assert.equal(
          dirty.querySelector('style'),
          null,
          'dangerous rawtext child removed from the returned root'
        );
        assert.equal(
          dirty.querySelector('span').textContent,
          'ok',
          'safe sibling content preserved'
        );

        if (dirty.parentNode) {
          dirty.parentNode.removeChild(dirty);
        }

        window.xssed = false;
      }
    );

    // Exploit variants: every root-kill reason this version has (the mXSS
    // check on rawtext roots, the fallback-tag check, the IN_PLACE entry
    // refusal of disallowed and forbidden roots), attached and parent-less
    // roots. Without the fix each root killed during the walk is handed
    // back. Each case either refuses the root, or whatever is handed back
    // must not re-open markup when the app stores and re-renders it
    // (serialize + plain HTML reparse). The reparse probe builds an <img>
    // without src, so nothing can load or fire in the live document.
    var CVE_109345_SINK = '<img onerror="window.__cve109345 = 1">';
    var cve109345ReparseSinks = function (node) {
      var probe = document.createElement('div');
      probe.innerHTML = node.outerHTML;
      var sinks = probe.querySelectorAll('img, script, [onerror], [onclick]');
      return sinks.length;
    };

    [
      {
        label: 'attached <style> root killed by the mXSS check',
        tag: 'style',
        attach: true,
        cfg: {},
        strict: true,
      },
      {
        label: 'parent-less <style> root killed by the mXSS check',
        tag: 'style',
        attach: false,
        cfg: {},
        strict: true,
      },
      {
        label: 'attached <xmp> root allowed via ADD_TAGS',
        tag: 'xmp',
        attach: true,
        cfg: { ADD_TAGS: ['xmp'] },
        strict: true,
      },
      {
        label: 'parent-less <xmp> root allowed via ADD_TAGS',
        tag: 'xmp',
        attach: false,
        cfg: { ADD_TAGS: ['xmp'] },
        strict: true,
      },
      {
        label: 'attached <noembed> root allowed via ADD_TAGS',
        tag: 'noembed',
        attach: true,
        cfg: { ADD_TAGS: ['noembed'] },
        strict: false,
      },
      {
        label: 'attached <style> root forbidden via FORBID_TAGS',
        tag: 'style',
        attach: true,
        cfg: { FORBID_TAGS: ['style'] },
        strict: true,
        entry: true,
      },
      {
        label: 'parent-less disallowed <xmp> root',
        tag: 'xmp',
        attach: false,
        cfg: {},
        strict: true,
        entry: true,
      },
      {
        label: 'attached HTML-namespace <svg> root killed by the namespace check',
        tag: 'svg',
        html: '<p></p>' + CVE_109345_SINK,
        attach: true,
        cfg: {},
        strict: true,
      },
    ].forEach(function (testCase) {
      QUnit.test(
        'CVE-2026-109345: IN_PLACE refuses a force-removed root: ' +
          testCase.label,
        function (assert) {
          withFreshPurify(function (purify) {
            var root = document.createElement(testCase.tag);
            root.setAttribute('onclick', 'window.__cve109345 = 2');
            if (testCase.html) {
              root.innerHTML = testCase.html;
            } else {
              root.textContent = '</' + testCase.tag + '>' + CVE_109345_SINK;
            }

            if (testCase.attach) {
              document.body.appendChild(root);
            }

            var cfg = { IN_PLACE: true };
            Object.keys(testCase.cfg).forEach(function (key) {
              cfg[key] = testCase.cfg[key];
            });

            var message = null;
            var ret = null;
            try {
              ret = purify.sanitize(root, cfg);
            } catch (error) {
              message = String(error && error.message);
            } finally {
              if (root.parentNode) {
                root.parentNode.removeChild(root);
              }
            }

            /* This version refuses a disallowed or forbidden root already
               at the IN_PLACE entry, before the walk starts. */
            var refusal = testCase.entry
              ? /root node is forbidden and cannot be sanitized in-place/
              : /refusing to sanitize in place/;
            var refused = refusal.test(message || '');
            var rootRemoved = purify.removed.some(function (entry) {
              return entry.element === root;
            });
            var sinks = ret ? cve109345ReparseSinks(ret) : 0;

            if (testCase.strict || rootRemoved) {
              assert.ok(
                refused,
                'force-removed IN_PLACE root must throw, got: ' +
                  message +
                  ', returned: ' +
                  (ret ? ret.outerHTML : ret)
              );
            } else {
              assert.ok(
                refused || ret === root,
                'root is refused or returned as-is, got: ' + message
              );
            }

            assert.equal(
              sinks,
              0,
              'nothing handed back re-opens markup on reparse: ' +
                (ret ? ret.outerHTML : ret)
            );
            if (!testCase.entry) {
              assert.equal(
                root.getAttribute('onclick'),
                null,
                'the on* handler on the root is cancelled'
              );
            }

            assert.notOk(window.__cve109345, 'no payload ran');
          });
        }
      );
    });

    QUnit.test('removeHook returns hook function', function (assert) {
      const entryPoint = 'afterSanitizeAttributes';
      const dirty = '<div class="hello"></div>';
      const expected = '<div class="world"></div>';

      DOMPurify.addHook(entryPoint, function (node) {
        return node.setAttribute('class', 'world');
      });
      assert.equal(DOMPurify.sanitize(dirty), expected);

      // remove hook and keep it
      const hookFunction = DOMPurify.removeHook(entryPoint);
      assert.equal(DOMPurify.sanitize(dirty), dirty);

      // set the same hook
      DOMPurify.addHook(entryPoint, hookFunction);
      assert.equal(DOMPurify.sanitize(dirty), expected);
    });
  };
});
