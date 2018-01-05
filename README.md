## burpContextAwareFuzzer

BurpSuite's payload-generation extension aiming at applying fuzzed test-cases depending on the type of payload (basic like integer, string, path; json; GWT; binary) and following encoding-scheme applied.

The project is just starting, so there is nothing working at the moment.

## Features

This extension is an answer to a generic problem while using BurpSuite's _Intruder_ tool: 
_what kind of payload am I dealing with, how it has been encoded, what test-cases to generate upon it and re-encode it to proper form?_

In order to accomplish it's task, the extension has to implement following features:

### Payload type detection

The extension has to detect with what kind of payload is it dealing with at the moment:
- Basic type, like: Integer, Float, Path, String
- JSON
- GWT
- unknown binary data
- Some serialized stream
- XML

Having detected type of payload, it will have to leverage that information to generate proper (according to the context) edge-case values, like integer overflows, path-traversal mutations and so on.

### Encoding detection and re-encoding

There are many situations in which the application is using some kind of encoding to pass around it's parameters. Among the others, the application may use:

- Base64 and Bas64 URL safe
- Hex encoding
- URL Encoding
- JWT
- Gzip
- combination of them

For instance, there might be payload like: `SGVsbG9Xb3JsZA%3d%3d` that is a result of `URLEncode(Base64('HelloWorld'))`. In order to get to the inner string, the fuzzer would have to peel of those encodings - mutate the value, and re-apply encodings in reversed order.

For this purpose, the extension will use following [gist](https://gist.github.com/mgeeky/1052681318a8164b112edfcdcb30798f).


## Installation and Usage

### Installation
In order to install that extension - download the `*.py` file, then in _Extender->Extension_ select _Add_. Then specify that extension is of type _Python_ (you will have to install [_Jython_](http://www.jython.org/downloads.html) first ).

Then, in your command line - install Python requistities:

On windows:
```
cmd> pip install jwt
cmd> pip install anytree
```

On linux:
```
$ sudo pip install jwt ; sudo pip install anytree
```
(in case _pip_ fails: try looking for packages like _python2-pyjwt_ ).


### Usage

This is a Payload Generation, so it comes into play in _Intruder_->_Payloads_->_Payload Type_->_Extension-generated_->_Selected generator_->**_Context-Aware Fuzzer_** . Having it specified as your payload-generator, you can start the attack and watch the payloads being mutated.
