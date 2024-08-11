.PHONY: all clean diff.pdf

all:
	npm install && ./node_modules/.bin/browserify parser.js -o bundledparser.js --standalone certificateparser && cp bundledparser.js ../app/js_lib/bundledparser.js

final: $(FILES_FINAL_PDF)

clean:
	$(RM) -r node_modules
	$(RM) package-lock.json
