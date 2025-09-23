#!/bin/sh

# Build command arguments based on environment variables
ARGS=""

if [ -n "$TS_STATE_DIR" ]; then
    ARGS="$ARGS -dir=$TS_STATE_DIR"
fi

if [ -n "$TS_HOSTNAME" ]; then
    ARGS="$ARGS -hostname=$TS_HOSTNAME"
fi

if [ -n "$TSIDP_USE_FUNNEL" ]; then
    ARGS="$ARGS -funnel"
fi

if [ -n "$TSIDP_ENABLE_STS" ]; then
    ARGS="$ARGS -enable-sts"
fi

if [ -n "$TSIDP_PORT" ]; then
    ARGS="$ARGS -port=$TSIDP_PORT"
fi

if [ -n "$TSIDP_LOCAL_PORT" ]; then
    ARGS="$ARGS -local-port=$TSIDP_LOCAL_PORT"
fi

#
# These flags will eventually be replaced
# with more specific logging flags.
#
if [ -n "$TSIDP_VERBOSE" ]; then
    ARGS="$ARGS -verbose"
fi

if [ -n "$TSIDP_ENABLE_DEBUG" ]; then
    ARGS="$ARGS -enable-debug"
fi

# Execute tsidp-server with the built arguments
exec /tsidp-server $ARGS "$@"