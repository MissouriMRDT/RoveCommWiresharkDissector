# RoveComm Wireshark Dissector

Custom dissector for Wireshark that parses and allows inspection of RoveComm protocol packets.

## Installing

1. Install Wireshark from [www.wireshark.org](https://www.wireshark.org/download.html).
2. Generate rovecomm.lua with compile.py.
3. Copy rovecomm.lua to the Wireshark personal plugins directory. By default, on Windows this is %APPDATA%\Wireshark\plugins and on Linux is ~/.wireshark/plugins/. Otherwise, check Wireshark > Help > About Wireshark > Folders > Personal Plugins.
4. After reloading Lua plugins with Ctrl+Shift+L, RoveComm packets should be recognized in any capture files (including saved files).
