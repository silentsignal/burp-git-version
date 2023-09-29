Burp Git Version
================

This Burp extension helps fingerprinting the version of remote software based on static artifacts by comparing them to a Git repository.

More information can be found in the [presentation](https://silentsignal.hu/docs/S2_BSidesVienna_2017_VSzA.pdf) and in the [talk recording](https://www.youtube.com/watch?v=opk8Vb7Q7iQ).

Usage (Burp)
------------

Select a number of Request-Response pairs corresponding to static artifacts belonging to the target software component from (e.g.: CSS, JS, documentations). This can typically be done on the Proxy or Target tabs. Bring up the right-click menu and select Extensions/Git version/Find version from Git.

A directory chooser window pops up, where you should select the locally stored `.git` directory of the target software.

The extensions matches file contents with the revisions stored in the Git repo, and reports a commit/time range that matches the static artifacts on the server.


