# Installation
- Download the latest `geckodriver` from https://github.com/mozilla/geckodriver/releases
- Install python dependencies `python3 -m pip install selenium matplotlib pandas`
- Bundle the browser extension with WASM support (i.e., `GOCACHE=true`) using `zip -1 -r ../extension-wasm.xpi *` in the [app](../app) folder
- Bundle the browser extension without WASM support (i.e., `GOCACHE=false`) using `zip -1 -r ../extension-js.xpi *` in the [app](../app) folder
- Download Alexa top domain list [top-1m.csv.zip](http://s3.amazonaws.com/alexa-static/top-1m.csv.zip)
