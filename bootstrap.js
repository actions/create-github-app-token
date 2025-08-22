// Enable env-based proxy support unless caller explicitly set NODE_USE_ENV_PROXY
if (process.env.NODE_USE_ENV_PROXY == null) {
  process.env.NODE_USE_ENV_PROXY = 1;
}

// Import main after environment prepared. Using dynamic import so this executes first even when bundled.
import("./main.js");
