
Debian
====================
This directory contains files used to package flexinodesd/flexinodes-qt
for Debian-based Linux systems. If you compile flexinodesd/flexinodes-qt yourself, there are some useful files here.

## flexinodes: URI support ##


flexinodes-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install flexinodes-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your flexinodesqt binary to `/usr/bin`
and the `../../share/pixmaps/flexinodes128.png` to `/usr/share/pixmaps`

flexinodes-qt.protocol (KDE)

