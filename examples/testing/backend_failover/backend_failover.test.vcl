// Test that all backends start healthy
// @scope: recv
// @suite: All backends should be healthy by default
sub test_all_backends_healthy {
  // Initially all backends are healthy
  assert.true(backend.backend1.healthy);
  assert.true(backend.backend2.healthy);
  assert.true(backend.backend3.healthy);
}

// Test backend health check variable
// @scope: recv
// @suite: Backend health status should be readable
sub test_backend_health_status {
  // Initially all backends are healthy
  assert.true(backend.backend1.healthy);
  assert.true(backend.backend2.healthy);
  assert.true(backend.backend3.healthy);
  
  // Mark backend1 as unhealthy
  testing.mock_backend_health(backend1, false);
  
  // Now backend1 should be unhealthy
  assert.false(backend.backend1.healthy);
  assert.true(backend.backend2.healthy);
  assert.true(backend.backend3.healthy);
}

// Test restoring backend health
// @scope: recv
// @suite: Backend health can be restored
sub test_restore_backend_health {
  // Mark backend1 as unhealthy
  testing.mock_backend_health(backend1, false);
  assert.false(backend.backend1.healthy);

  // Restore backend1 to healthy
  testing.mock_backend_health(backend1, true);
  assert.true(backend.backend1.healthy);
}

