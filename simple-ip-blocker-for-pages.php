<?php
/*
Plugin Name: Simple IP Blocker for Pages
Description: Block specific IP addresses or IPv4 CIDR ranges from accessing selected pages. Safe admin UI and messages with HTML.
Version: 1.8.6.4
Author: Philippe
License: GPL-2.0-or-later
Text Domain: simple-ip-blocker
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
* Activation: set default options
*/
function sib_activate() {
	add_option( 'sib_pages', [] );
	add_option( 'sib_ips', '' );
	add_option( 'sib_block_message', 'Access denied. Your IP address has been blocked from viewing this page.' );
	add_option( 'sib_redirect_url', '' );
}
register_activation_hook( __FILE__, 'sib_activate' );

/**
* Normalise une liste brute en tableau
*/
function sib_normalize_ip_list( $raw ) {
	$lines = array_map( 'trim', preg_split( '/\r\n|\r|\n/', (string) $raw ) );
	$lines = array_filter(
		$lines,
		function ( $ip ) {
			return $ip !== '' && preg_match( '/^[0-9a-fA-F:\.\/]+$/', $ip );
		}
	);
	$lines = array_unique( $lines );
	sort( $lines, SORT_STRING );
	return $lines;
}

/**
* Utilitaire: correspondance IP client vs patterns
*/
function sib_ip_matches( $client_ip, $patterns ) {
	if ( in_array( $client_ip, $patterns, true ) ) {
		return true;
	}

	$is_client_ipv4 = filter_var( $client_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
	if ( $is_client_ipv4 ) {
		$client_long = ip2long( $client_ip );
		if ( $client_long !== false ) {
			foreach ( $patterns as $p ) {
				if ( strpos( $p, '/' ) === false ) {
					continue;
				}
				list($subnet, $mask_bits) = explode( '/', $p, 2 );
				$mask_bits                = is_numeric( $mask_bits ) ? (int) $mask_bits : -1;

				if ( ! filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
					continue;
				}
				if ( $mask_bits < 0 || $mask_bits > 32 ) {
					continue;
				}
				$subnet_long = ip2long( $subnet );
				if ( $subnet_long === false ) {
					continue;
				}

				$netmask = ( $mask_bits === 0 ) ? 0 : ( ~( ( 1 << ( 32 - $mask_bits ) ) - 1 ) & 0xFFFFFFFF );

				if ( ( $client_long & $netmask ) === ( $subnet_long & $netmask ) ) {
					return true;
				}
			}
		}
	}
	return false;
}

/**
* Menu admin
*/
function sib_add_admin_menu() {
	add_menu_page(
		__( 'Simple IP Blocker', 'simple-ip-blocker' ),
		__( 'IP Blocker', 'simple-ip-blocker' ),
		'manage_options',
		'simple-ip-blocker',
		'sib_render_settings_page',
		'dashicons-shield-alt',
		80
	);
	add_submenu_page(
		'simple-ip-blocker',
		__( 'Manage Blocked IPs', 'simple-ip-blocker' ),
		__( 'Manage IPs', 'simple-ip-blocker' ),
		'manage_options',
		'simple-ip-blocker-ips',
		'sib_render_manage_ips_page'
	);
}
add_action( 'admin_menu', 'sib_add_admin_menu' );

/**
* Register settings
*/
function sib_admin_init() {
	register_setting( 'sib_options_group', 'sib_pages', [ 'type' => 'array', 'sanitize_callback' => 'sib_sanitize_pages' ] );
	register_setting( 'sib_options_group', 'sib_block_message', [ 'type' => 'string', 'sanitize_callback' => 'wp_kses_post' ] );
	register_setting( 'sib_options_group', 'sib_redirect_url', [ 'type' => 'string', 'sanitize_callback' => 'esc_url_raw' ] );

	add_action( 'admin_post_sib_add_ips', 'sib_handle_add_ips' );
}
add_action( 'admin_init', 'sib_admin_init' );

/**
* Sanitizer pages
*/
function sib_sanitize_pages( $value ) {
	$clean = [];
	if ( is_array( $value ) ) {
		foreach ( $value as $id ) {
			$id = absint( $id );
			if ( $id > 0 ) {
				$clean[] = $id;
			}
		}
	}
	return $clean;
}

/**
* Handler: ajout d’IPs / ranges
*/
function sib_handle_add_ips() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Unauthorized', 'simple-ip-blocker' ), esc_html__( 'Error', 'simple-ip-blocker' ), [ 'response' => 403 ] );
	}
	check_admin_referer( 'sib_add_ips_action' );

	$new_raw = '';
	if ( isset( $_POST['sib_new_ips'] ) ) {
		$new_raw = sanitize_textarea_field( wp_unslash( $_POST['sib_new_ips'] ) );
	}

	$existing_raw = (string) get_option( 'sib_ips', '' );

	$existing = sib_normalize_ip_list( $existing_raw );
	$new      = sib_normalize_ip_list( $new_raw );

	$merged = array_unique( array_merge( $existing, $new ) );
	sort( $merged, SORT_STRING );
	update_option( 'sib_ips', implode( "\n", $merged ) );

	wp_safe_redirect( add_query_arg( [ 'page' => 'simple-ip-blocker', 'sib_ips_added' => '1' ], admin_url( 'admin.php' ) ) );
	exit;
}

/**
* Lien Settings dans la liste des plugins
*/
function sib_add_settings_link( $links ) {
	$settings_link = '<a href="admin.php?page=simple-ip-blocker">' . esc_html__( 'Settings', 'simple-ip-blocker' ) . '</a>';
	array_unshift( $links, $settings_link );
	return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'sib_add_settings_link' );

/**
* Settings page (main)
*/
function sib_render_settings_page() {
	$pages        = (array) get_option( 'sib_pages', [] );
	$message      = (string) get_option( 'sib_block_message', '' );
	$redir        = (string) get_option( 'sib_redirect_url', '' );
	$current_ip   = '';
	
	// Validation stricte de REMOTE_ADDR
	if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
		$current_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
	}

	$ips_raw  = (string) get_option( 'sib_ips', '' );
	$ips_list = sib_normalize_ip_list( $ips_raw );
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Simple IP Blocker for Pages', 'simple-ip-blocker' ); ?></h1>

		<?php
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- View logic only, no action taken.
		if ( isset( $_GET['settings-updated'] ) && sanitize_text_field( wp_unslash( $_GET['settings-updated'] ) ) ) :
			?>
			<div class="notice notice-success is-dismissible">
				<p><strong><?php esc_html_e( 'Settings saved successfully.', 'simple-ip-blocker' ); ?></strong></p>
			</div>
		<?php endif; ?>

		<?php
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- View logic only, no action taken.
		if ( isset( $_GET['sib_ips_added'] ) && sanitize_text_field( wp_unslash( $_GET['sib_ips_added'] ) ) ) :
			?>
			<div class="notice notice-success is-dismissible">
				<p><strong><?php esc_html_e( 'New IPs added successfully.', 'simple-ip-blocker' ); ?></strong></p>
			</div>
		<?php endif; ?>

		<form method="post" action="options.php">
			<?php settings_fields( 'sib_options_group' ); ?>

			<div class="card" style="max-width: 100%; margin-top: 20px; padding: 1em;">
				<h2><?php esc_html_e( 'Pages to protect', 'simple-ip-blocker' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Select the pages you want to block access to.', 'simple-ip-blocker' ); ?></p>
				
				<select name="sib_pages[]" multiple size="8" style="width:100%; max-width:400px;">
					<?php
					$all_pages = get_pages( [ 'sort_column' => 'post_title', 'sort_order' => 'ASC' ] );
					foreach ( $all_pages as $p ) {
						printf(
							'<option value="%s" %s>%s</option>',
							esc_attr( $p->ID ),
							selected( in_array( $p->ID, $pages ), true, false ),
							esc_html( $p->post_title )
						);
					}
					?>
				</select>
			</div>

			<div class="card" style="max-width: 100%; margin-top: 20px; padding: 1em;">
				<h2><?php esc_html_e( 'Block message', 'simple-ip-blocker' ); ?></h2>
				<textarea id="sib_block_message" name="sib_block_message" rows="3" class="large-text"><?php echo esc_textarea( $message ); ?></textarea>
				
				<p><em><?php esc_html_e( 'Preview (safe HTML):', 'simple-ip-blocker' ); ?></em></p>
				<div style="border:1px solid #ccc; padding:10px; background:#fff;"><?php echo wp_kses_post( $message ); ?></div>
				
				<p class="description"><?php echo wp_kses_post( __( 'Safe HTML allowed (e.g. <strong>, <em>, <a>). Filtered by wp_kses_post.', 'simple-ip-blocker' ) ); ?></p>
			</div>

			<div class="card" style="max-width: 100%; margin-top: 20px; padding: 1em;">
				<h2><?php esc_html_e( 'Redirect URL (optional)', 'simple-ip-blocker' ); ?></h2>
				<input type="url" name="sib_redirect_url" value="<?php echo esc_attr( $redir ); ?>" class="regular-text" placeholder="https://example.com/blocked" />
			</div>

			<?php submit_button( esc_html__( 'Save settings', 'simple-ip-blocker' ) ); ?>
		</form>

		<div class="card" style="max-width: 100%; margin-top: 20px; padding: 1em;">
			<h2><?php esc_html_e( 'Add new blocked IPs or IPv4 CIDR ranges', 'simple-ip-blocker' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'sib_add_ips_action' ); ?>
				<input type="hidden" name="action" value="sib_add_ips" />
				
				<textarea name="sib_new_ips" rows="4" cols="60" placeholder="<?php esc_attr_e( 'One per line (e.g. 203.0.113.7 or 192.168.1.0/24)', 'simple-ip-blocker' ); ?>"></textarea>
				
				<p><small><?php esc_html_e( 'Your current IP is:', 'simple-ip-blocker' ); ?> <strong><?php echo esc_html( $current_ip ); ?></strong></small></p>
				<?php submit_button( esc_html__( 'Add IPs', 'simple-ip-blocker' ) ); ?>
			</form>

			<?php if ( ! empty( $ips_list ) ) : ?>
				<h3><?php esc_html_e( 'Currently blocked IPs / ranges', 'simple-ip-blocker' ); ?></h3>
				<p><a href="admin.php?page=simple-ip-blocker-ips"><?php esc_html_e( 'Manage blocked IPs', 'simple-ip-blocker' ); ?></a></p>
				<ul style="list-style:disc; padding-left:20px;">
					<?php foreach ( $ips_list as $ip ) : ?>
						<li><?php echo esc_html( $ip ); ?></li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</div>
	</div>
	<?php
}

/**
* Manage IPs page (subpage)
*/
function sib_render_manage_ips_page() {
	$ips_raw = (string) get_option( 'sib_ips', '' );
	$ips     = sib_normalize_ip_list( $ips_raw );

	// Initial check to see if form was submitted
	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Check happens inside via check_admin_referer.
	if ( isset( $_POST['sib_delete_ips'] ) && isset( $_POST['delete_ips'] ) ) {
		
		check_admin_referer( 'sib_delete_ips_action' );
		
		// On récupère les données brutes. 
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitization is done via array_map below.
		$raw_deletes = wp_unslash( $_POST['delete_ips'] );

		if ( is_array( $raw_deletes ) ) {
			$to_delete = array_map( 'sanitize_text_field', $raw_deletes );
			$to_delete = array_map( 'trim', $to_delete );

			$remaining = array_values( array_diff( $ips, $to_delete ) );
			$remaining = array_unique( $remaining );
			sort( $remaining, SORT_STRING );
			update_option( 'sib_ips', implode( "\n", $remaining ) );
			$ips = $remaining;
			
			echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__( 'Selected IPs deleted successfully.', 'simple-ip-blocker' ) . '</strong></p></div>';
		}
	}
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Manage Blocked IPs', 'simple-ip-blocker' ); ?></h1>

		<p style="margin-bottom:20px;">
			<a href="admin.php?page=simple-ip-blocker" class="button">&larr; <?php esc_html_e( 'Back to Settings', 'simple-ip-blocker' ); ?></a>
		</p>

		<?php if ( empty( $ips ) ) : ?>
			<p><?php esc_html_e( 'No IPs are currently blocked.', 'simple-ip-blocker' ); ?></p>
		<?php else : ?>
			<form method="post">
				<?php wp_nonce_field( 'sib_delete_ips_action' ); ?>
				<table class="widefat fixed striped">
					<thead>
						<tr>
							<td id="cb" class="manage-column column-cb check-column"><input type="checkbox" id="sib_check_all"></td>
							<th><?php esc_html_e( 'Blocked IP / Range', 'simple-ip-blocker' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $ips as $ip ) : ?>
							<tr>
                                <th scope="row" class="check-column"><input type="checkbox" name="delete_ips[]" value="<?php echo esc_attr( $ip ); ?>"></th>
								<td><?php echo esc_html( $ip ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php submit_button( esc_html__( 'Delete selected', 'simple-ip-blocker' ), 'delete', 'sib_delete_ips' ); ?>
			</form>
			<script>
			document.getElementById('sib_check_all').addEventListener('change', function() {
				var checkboxes = document.querySelectorAll('input[name="delete_ips[]"]');
				for (var i = 0; i < checkboxes.length; i++) {
					checkboxes[i].checked = this.checked;
				}
			});
			</script>
		<?php endif; ?>
	</div>
	<?php
}

/**
* Front-end blocking
*/
function sib_template_redirect() {
	$pages   = (array) get_option( 'sib_pages', [] );
	$ips_raw = (string) get_option( 'sib_ips', '' );
	
	$default_msg = __( 'Access denied. Your IP address has been blocked from viewing this page.', 'simple-ip-blocker' );
	$message     = (string) get_option( 'sib_block_message', $default_msg );
	
	$redir = (string) get_option( 'sib_redirect_url', '' );

	if ( ! empty( $pages ) && is_page( $pages ) ) {
		$client_ip = '';
		if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$client_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		$patterns = sib_normalize_ip_list( $ips_raw );

		if ( ! empty( $client_ip ) && ! empty( $patterns ) && sib_ip_matches( $client_ip, $patterns ) ) {
			if ( $redir !== '' ) {
				wp_safe_redirect( $redir, 302 );
				exit;
			}
			status_header( 403 );
			
			wp_die(
				wp_kses_post( $message ), 
				esc_html__( 'Access denied', 'simple-ip-blocker' ), 
				[ 'response' => 403 ]
			);
		}
	}
}
add_action( 'template_redirect', 'sib_template_redirect', 0 );
