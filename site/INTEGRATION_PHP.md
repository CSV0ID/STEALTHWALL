#  PHP & WordPress Integration Guide

This guide explains how to protect any **PHP**, **Laravel**, or **WordPress** website using StealthWall.

---

## 1. Zero-Code Integration via `auto_prepend_file`

By configuring `auto_prepend_file`, StealthWall intercepts requests **before WordPress or your PHP scripts execute**, blocking attackers before MySQL database queries or PHP scripts run.

### In `php.ini` or `.user.ini`:
```ini
auto_prepend_file = "/path/to/stealthwall/integrations/php/stealthwall.php"
```

---

## 2. WordPress Setup (`wp-config.php`)

Alternatively, include `stealthwall.php` at the very top of `wp-config.php`:

```php
<?php
// Top of wp-config.php
require_once __DIR__ . '/stealthwall.php';

// ... rest of WordPress configuration ...
```

---

## 3. How `stealthwall.php` Operates

1. Extracts the true visitor IP from `CF-Connecting-IP`, `X-Forwarded-For`, or `REMOTE_ADDR`.
2. Queries the local StealthWall daemon (`http://127.0.0.1:9377/internal/decide`) with a strict `50ms` curl timeout.
3. If an attack signature (e.g. WPScan, SQLMap, brute-force) is detected:
   - Sets HTTP Response Code `403 Forbidden`.
   - Sends a JSON rejection payload.
   - Calls `exit` immediately to prevent MySQL execution.
