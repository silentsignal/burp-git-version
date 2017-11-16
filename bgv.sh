#!/bin/sh
java -cp $(ls lib/*.jar | tr '\n' ':')build burp.BurpExtender $@
