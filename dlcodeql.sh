#!/bin/bash

codeql pack download codeql/cpp-queries codeql/python-queries codeql/javascript-queries codeql/java-queries codeql/csharp-queries codeql/go-queries codeql/ruby-queries

echo "Downloading CodeQL packs... This may take a while."
wait -n
