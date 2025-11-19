=== Simple IP Blocker for Pages ===
Contributors: philippe Mathis
Donate link: https://buymeacoffee.com/pmathis
Tags: ip, block, security, pages, ban, spam
Requires at least: 5.0
Tested up to: 6.7
Stable tag: 1.8.6.4
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Block specific IPv4 addresses or CIDR ranges from accessing selected WordPress pages.
Lightweight, simple, and user-friendly.

== Description ==

Simple IP Blocker for Pages allows administrators to restrict access to selected pages based on visitor IP addresses.
It is designed to be lightweight and easy to use, without complex configuration.

**Features:**
- Block exact IPv4 addresses or CIDR ranges (e.g., 192.168.1.0/24).
- Select one or more pages to protect.
- Customize the block message with safe HTML.
- Optionally redirect blocked visitors to another URL.
- Simple admin interface with clear feedback messages.

== Installation ==

1. **Install and Activate:** Install the plugin via the WordPress plugins screen (Search for "Simple IP Blocker") or by uploading the ZIP file. Activate it immediately.
2. **Access Settings:** Go to **IP Blocker** in your WordPress admin menu.
3. **Select Pages to Protect:** In the **Pages to protect** section, select the pages that should restrict access (Use Ctrl/Cmd for multi-selection).
4. **Customize Block Action:** Define a custom **Block message** and/or an **optional Redirect URL** (e.g., https://example.com/login).
5. **Add IPs/Ranges:** In the "Add new blocked IPs" section, enter IP addresses or CIDR ranges, one per line (e.g., `203.0.113.45` or `192.168.1.0/24`).
6. **Save:** Click **Save settings** to apply the configuration.
7. **Manage:** Use the **Manage IPs** sub-menu to view and remove existing blocked entries.

== Frequently Asked Questions ==

= Can I block IP ranges? =
Yes. You can block exact IPv4 addresses or use CIDR notation (e.g., `192.168.0.0/24`) to block a range of IPs.

= What happens when a blocked IP visits a protected page? =
They will either see your custom block message or be redirected to the URL you specify in the settings.

= Is HTML allowed in the block message? =
Yes, safe HTML tags such as `<strong>`, `<em>`, and `<a>` are allowed. All content is filtered through `wp_kses_post` for security.

== Screenshots ==

1. Settings page with page selection and block message.
2. Add new blocked IPs form.
3. Manage blocked IPs list.

== Changelog ==

= 1.8.6.4 =
* Security Update: Implemented strict sanitization and nonce verification to meet WordPress.org standards.
* Fix: Improved CIDR range handling logic.

= 1.8.6 =
* Initial stable release with IP blocking and admin interface.

== Upgrade Notice ==

= 1.8.6.4 =
This update includes critical security improvements and sanitization fixes required for WordPress standards compliance.
