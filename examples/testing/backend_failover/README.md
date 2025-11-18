# Backend Failover Testing Example

This example demonstrates how to test backend failover logic using the `testing.mock_backend_health()` function.

## Overview

The example includes:
- Multiple backend definitions (backend1, backend2, backend3)
- A fallback director that tries backends in order
- A random director with quorum configuration
- Comprehensive tests for various failover scenarios

## Running the Tests

```shell
falco test -I . ./backend_failover.vcl
```

## Test Scenarios

### Fallback Director Tests

1. **All backends healthy** - Verifies the first backend is selected
2. **Primary backend unhealthy** - Verifies failover to the second backend
3. **Two backends unhealthy** - Verifies failover to the third backend
4. **All backends unhealthy** - Verifies error state when no backends are available

### Random Director Tests

1. **Quorum met** - Verifies director works when enough backends are healthy
2. **Quorum not met** - Verifies error state when quorum threshold is not reached

### Health Status Tests

1. **Reading health status** - Verifies `backend.{name}.healthy` variable
2. **Restoring health** - Verifies backends can be marked healthy again

## Key Function

### `testing.mock_backend_health(BACKEND backend, BOOL healthy)`

Sets the health status of a backend for testing purposes.

**Parameters:**
- `backend` - The backend to modify (e.g., `backend1`)
- `healthy` - Boolean value: `true` for healthy, `false` for unhealthy

**Example:**
```vcl
// Mark backend as unhealthy
testing.mock_backend_health(backend1, false);

// Mark backend as healthy
testing.mock_backend_health(backend1, true);
```

## Use Cases

This testing approach is useful for:
- Validating director failover logic
- Testing quorum configurations
- Verifying error handling when all backends fail
- Testing backend selection algorithms
- Ensuring proper health check integration

