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

# logging control
if [ -n "$TSIDP_LOG" ]; then
    case "$TSIDP_LOG" in
        debug|info|warn|error)
            ARGS="$ARGS -log=$TSIDP_LOG"
            ;;
        *)
            echo "Error: TSIDP_LOG_LEVEL must be one of: debug, info, warn, error"
            echo "Current value: $TSIDP_LOG"
            exit 1
            ;;
    esac
fi

if [ -n "$TSIDP_DEBUG_ALL_REQUESTS" ]; then
    ARGS="$ARGS -debug-all-requests"
fi

if [ -n "$TSIDP_DEBUG_TSNET" ]; then
    ARGS="$ARGS -debug-tsnet"
fi

# Execute tsidp-server with the built arguments
exec /tsidp-server $ARGS "$@"