# Auf dem Mac:  make     (Xcode-Kommandozeilentools + Node/npx fuer esbuild)
# Ablauf: debug_ios.ts -> script.js (esbuild) -> blobs.c -> kitmod.dylib
SDK  = $(shell xcrun --sdk iphoneos --show-sdk-path)
CC   = xcrun --sdk iphoneos clang
QJS  = ../third_party/quickjs
FLAGS = -arch arm64 -isysroot $(SDK) -miphoneos-version-min=14.0 -O2 -fvisibility=hidden -D_GNU_SOURCE -I$(QJS) -I.
TS   ?= ../debug_ios.ts

kitmod.dylib: kitmod.c km_runtime.c kitmod_gen.h kitmod_tramp.S blobs.c
	$(CC) $(FLAGS) -dynamiclib -install_name @rpath/kitmod.dylib -o $@ \
	  kitmod.c km_runtime.c kitmod_tramp.S blobs.c \
	  $(QJS)/quickjs.c $(QJS)/libregexp.c $(QJS)/libunicode.c $(QJS)/dtoa.c

script.js: $(TS)
	npx --yes esbuild $(TS) --format=iife --target=es2020 --outfile=$@

blobs.c: prelude.js script.js ../tools/embed.py
	python3 ../tools/embed.py prelude.js script.js $@

clean:
	rm -f kitmod.dylib script.js blobs.c
