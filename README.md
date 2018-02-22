# Fun with extended bitcoin keys (BIP 32)

## Warnings
First and foremost, do not use this code. I can't stress that enough. Literally nothing here fully implements any of the specs defined by any of the standards. And it's not exactly the best Python code I've ever written (:sorrynotsorry:).

Here are just some of the ways this is incomplete (and will never be finished):
* poor distinction between compressed and uncompressed private/public keys
* no hardening in the extended keys
* no validation of checksum errors
* I never even tested creating more than one child per generation

## What is this
I wrote this to satisfy my skepticism that child XPUBs could in fact be created without their corresponding XPRVs. And... they can! Way cool. And that led to me writing a blog post. BIP 32 is really pretty neat.

Other things of note here:
1. This is my first attempt at using mypy and static typing in lieu of heavy classes to manage complex typing (not everywhere, just the tricky internals), and I mostly like it. It makes some things harder to read, but it def caught some bugs.
2. This is intentionally not built to be an includable python package (e.g. it's only python 3.6). Don't include it. Seriously. This is not an endorsement, but https://github.com/prusnak/bip32utils has implemented way more than I have. Maybe start there?

## Running it

1. get into a python 3.6 environment
2. install dependencies
```shell
pip install -r requirements.txt
```
3. run it
```shell
python run_me.py
```

## Running the tests

Maybe something like this?
```shell
python tests.py && mypy xpub_stuff
```


## Links
Remember when websites used to have a page of links??
* blog post: UPDATE-FOR-LINK
* full spec for extended keys: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
