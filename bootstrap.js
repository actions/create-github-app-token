// Enable env-based proxy support (honors explicit opt-out if caller set NODE_USE_ENV_PROXY)
if (process.env.NODE_USE_ENV_PROXY == null) {
  process.env.NODE_USE_ENV_PROXY = "1";
}

// Defer to original main entry (dynamic import ensures above code runs first)
await import("./main.js");
