# Chrome GPU Compatibility Experiments

This branch contains the standalone Chrome experiment and its supporting
checks. Start with the [Chrome workflow and safety notes](minimal/README.md).

The implementation, preparation tools, and tests are in [`minimal/`](minimal/).
The root-level [`chrome_main.c`](chrome_main.c) is retained because the optional
`--inject-launcher` mode in `minimal/patch_chrome.py` uses it.
