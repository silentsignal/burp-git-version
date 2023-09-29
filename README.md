Burp Git Version
================

This Burp extension helps fingerprinting the version of remote software based on static artifacts by comparing them to a Git repository.

More information can be found in the [presentation](https://silentsignal.hu/docs/S2_BSidesVienna_2017_VSzA.pdf) and in the [talk recording](https://www.youtube.com/watch?v=opk8Vb7Q7iQ).

Usage (Burp)
------------

Select a number of Request-Response pairs corresponding to static artifacts belonging to the target software component from (e.g.: CSS, JS, documentations). This can typically be done on the Proxy or Target tabs. Bring up the right-click menu and select Extensions/Git version/Find version from Git.

A directory chooser window pops up, where you should select the locally stored `.git` directory of the target software.

The extensions matches file contents with the revisions stored in the Git repo, and reports a commit/time range that matches the static artifacts on the server.

Usage (Command Line)
--------------------

The JAR can also be used as a standalone utility:

```
java -cp burp-git-version.jar:burp-extender-api-2.3.jar burp.BurpExtender /path/to/.git <githash0> <githash1> ...
```

You can grab the Burp Extender API definition from [Maven](https://mvnrepository.com/artifact/net.portswigger.burp.extender/burp-extender-api/2.3) or similar repository.

It's important to note that the command-line interface expects Git object hashes instead of file paths. The Git hashes are not plain-old SHA-1's, you can generate them like this:

```
git hash-object <filename>
```


