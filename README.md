# mortcms - A Simple, Modern CMS for MORT

## Goals
1. Maintainability
  - Easy to understand
  - No code required for common tasks
2. Simplicity
  - Good Comments
  - No custom magic
  - Use of good libraries where possible
3. Speed
  - Look more professional with a more responsive website

## Dependencies
We use external libraries to do as much heavy lifting as possible,
so we depend on:
- flask
  - Flask-SQLAlchemy
  - Flask-Assets
- pycrypto

## Tradeoffs made for Goals
We've had to make a few design choices in pursuit of the goals above.
- CDN Use
  - We use CDNs for non-debug runs as they ensure good delivery of prebuilt libraries
  - If mortcms is run in debug mode, resources are served unminified to ease debugging
  

## TODO
- Setup lesscss so we can use Bootstrap mixins
