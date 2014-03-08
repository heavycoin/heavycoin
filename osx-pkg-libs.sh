#!/bin/bash

for f in $(otool -L ./Heavycoin-Qt.app/Contents/MacOS/Heavycoin-Qt | tail -r | cut -f 2 | grep -Ev "^(\.|\/usr\/lib\/|\/System\/Library)" | cut -d ' ' -f 1); do
    cp -v $f ./Heavycoin-Qt.app/Contents/MacOS/
    install_name_tool -change $f @executable_path/$(basename $f) ./Heavycoin-Qt.app/Contents/MacOS/Heavycoin-Qt
done

cp -a /opt/local/Library/Frameworks/QtGui.framework/Versions/4/Resources/qt_menu.nib ./Heavycoin-Qt.app/Contents/Resources/
