if test -z "$PICOSOCKS5_VERSION"
then
    PICOSOCKS5_VERSION=`git describe --tags --match 'v[0-9]*' --always --dirty 2>/dev/null`
fi
if test -z "$PICOSOCKS5_VERSION"
then
    PICOSOCKS5_VERSION=`cat VERSION 2>/dev/null`
fi
if test -z "$PICOSOCKS5_VERSION"
then
    PICOSOCKS5_VERSION="[na]"
fi
echo "$PICOSOCKS5_VERSION"
