<?php
/**
 * Plugin Name: PHP-OAuth2 Protocol Wrapper
 * Plugin URI: https://github.com/wlcdesigns/PHP-OAuth2
 * Description: This super-basic WordPress plugin is an OAuth2 wrapper based off PHP-OAuth2.
 * Version: 1.0.0
 * Author: Charron Pierrick / Berejeb Anis / wLc Designs
 * Author URI: http://wlcdesigns.com
 * License: GNU LGPL
 */

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

require('PHP-OAuth2/Client.php');
require('PHP-OAuth2/GrantType/IGrantType.php');
require('PHP-OAuth2/GrantType/AuthorizationCode.php');	

class iOS_WP_OAuth_Login
{	
	//Initialize
	public function _ios_wp_oauth_init()
	{
		$this->_ios_wp_login();
		$this->_ios_wp_oauth();
		add_filter('wo_endpoints', array($this, '_ios_wp_update_endpoint'), 2);
	}
	
	//Create Update Me endpoint
	public function _ios_wp_update_endpoint($methods)
	{
		$methods['update-me'] = array(
			'func'=> array($this, 'run_update_method'), // Function name to run
		    'public' => false // True to be public
		);
		
		return $methods;
	}
	
	//Update Display Name method
	public function run_update_method($token = null)
	{
		$response = new OAuth2\Response();
		
		if (!isset($token['user_id']) || $token['user_id'] == 0) {
			
			$response->setError(400, 'invalid_request', 'Missing or invalid access token');
			$response->send();
			exit;
		}
		
		$user_id = &$token['user_id'];
		
		if( !current_user_can('edit_user', $user_id) ){
			$response->setError(400, 'invalid_request', 'You are not allowed to edit this user');
			$response->send();
			exit;
		}

		$user_id = wp_update_user( 
			array( 
				'ID' => $user_id, 
				'display_name' => sanitize_text_field($_POST['name'])
			) 
		);
		
		if ( is_wp_error( $user_id ) ) {
			// There was an error, probably that user doesn't exist.
			$response->setError(400, 'invalid_request', 'There was an error updating me');
			$response->send();
			exit;
			
		} else {
			$return = array('success'=>'updated-me');
			$response = new OAuth2\Response($return);
			$response->send();
			exit();
		}
	}
	
	public function _ios_wp_oauth()
	{
		$oauth_links = $this->oauth_links();
		$client = new PHPOAuth2\Client($oauth_links['client_id'], $oauth_links['client_secret']);
		
		if(isset($_REQUEST['ioswpoauth']))
		{			
			$params = array(
				'code' => sanitize_text_field($_REQUEST['code']), 
				'redirect_uri' => $oauth_links['redirect_uri']
			);
			
			//Access Token Request Leg
			$response = $client->getAccessToken(
				$oauth_links['token_endpoint'], 
				'authorization_code', 
				$params
			);
			
			//Send tokens to iOS App
			echo json_encode( $response );
			exit();
		}
		
		if( isset($_POST['ios_wp_oauth']) )
		{					
			switch($_POST['ios_wp_oauth'])
			{
				case 1: //Redirtect to get access token
				
					if( !is_user_logged_in() ){ return; }
					
					//Run Authentication Legs
	
					$auth_url = $client->getAuthenticationUrl(
				    	$oauth_links['authorization_endpoint'], 
				    	$oauth_links['redirect_uri']
				    );
				    
				    //Got code, off to next leg
				    
				    header('Location: ' . $auth_url);
				    die('Redirect');
			    
				break;
				
				case 2: //Fetch refresh token
				
				  	$refresh = wp_remote_post( $oauth_links['token_endpoint'],
				  	array(
				  		'body' => array( 
				  			'grant_type' => 'refresh_token', 
				  			'refresh_token' => sanitize_text_field($_POST['refresh_token']),
				  			'client_id' => $oauth_links['client_id'],
				  			'client_secret' => $oauth_links['client_secret'],
				  		),
				  	));
				  	
					if ( is_wp_error( $refresh ) ) {
					
						$error_message = $response->get_error_message();
						echo json_encode($error_message);
						
					} else {

						if( !empty($refresh['body']) ){
							echo json_encode($refresh['body']);
						}
					}
					
					exit();
					
				break;
			}
		}
	}
	
	//func get user data
	public function _ios_wp_user_data()
	{	
		$message = array();
		//wp_signon sanitizes login input
		$user = wp_signon( array(
			'user_login' => $_POST['ios_userlogin'],
			'user_password' => $_POST['ios_userpassword'],
			'remember' => true
		), false );
		
		if ( is_wp_error($user) )
		{
			//Return error messages
			if(isset($user->errors['invalid_username'])){
				$message['error'] = "Invalid User Name";
			} elseif(isset($user->errors['incorrect_password'])){
				$message['error'] = "Incorrect Password";
			}
			
			echo json_encode($message);
			exit(); 
		}
		else
		{
			/*
			 * Don't return anymore information than needed. 
			 * In this case we only need the user ID
			 * But add more as needed
			 */
			 
			$id = array(
				'ID' => $user->ID
			); 
				
			echo json_encode( $id );
			exit();
		}
	}
	
	//Run user data method upon attempted login
	public function _ios_wp_login()
	{	
		if( isset($_POST['ios_wp_login']) ){
			$this->_ios_wp_user_data();
		}
	}
	
	//Set the OAuth links
	protected function oauth_links()
	{
		$php_oauth2_protocol_options = get_option( 'php_oauth2_protocol_option_name' ); 
		$client_id = $php_oauth2_protocol_options['client_id_0'];
		$client_secret = $php_oauth2_protocol_options['client_secret_1'];
		$redirect_uri = $php_oauth2_protocol_options['redirect_uri_2']; 
		
		return array(
			'client_id' => $client_id, //Client ID
			'client_secret' => $client_secret, //Client Secret
			'redirect_uri' => $redirect_uri, //Redirect Link
			'authorization_endpoint' => home_url('oauth/authorize'),
			'token_endpoint' => home_url('oauth/token'),
		);
	}
}

add_action('after_setup_theme', array($ios_oauth_login = new iOS_WP_OAuth_Login,'_ios_wp_oauth_init'));


class PHPOAuthProtocol {
	private $php_oauth2_protocol_options;

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'php_oauth2_protocol_add_plugin_page' ) );
		add_action( 'admin_init', array( $this, 'php_oauth2_protocol_page_init' ) );
	}

	public function php_oauth2_protocol_add_plugin_page() {
		add_management_page(
			'PHP-OAuth2 Protocol', // page_title
			'PHP-OAuth2 Protocol', // menu_title
			'manage_options', // capability
			'php-oauth2-protocol', // menu_slug
			array( $this, 'php_oauth2_protocol_create_admin_page' ) // function
		);
	}

	public function php_oauth2_protocol_create_admin_page() {
		$this->php_oauth2_protocol_options = get_option( 'php_oauth2_protocol_option_name' ); ?>

		<div class="wrap">
			<h2>PHP-OAuth2 Protocol</h2>
			<p>This plugin handles the HTTP requests for OAuth2 authorization. Must have the OAuth2 server plugin installed for this to work. </p>
			<?php settings_errors(); ?>

			<form method="post" action="options.php">
				<?php
					settings_fields( 'php_oauth2_protocol_option_group' );
					do_settings_sections( 'php-oauth2-protocol-admin' );
					submit_button();
				?>
			</form>
		</div>
	<?php }

	public function php_oauth2_protocol_page_init() {
		register_setting(
			'php_oauth2_protocol_option_group', // option_group
			'php_oauth2_protocol_option_name', // option_name
			array( $this, 'php_oauth2_protocol_sanitize' ) // sanitize_callback
		);

		add_settings_section(
			'php_oauth2_protocol_setting_section', // id
			'Settings', // title
			array( $this, 'php_oauth2_protocol_section_info' ), // callback
			'php-oauth2-protocol-admin' // page
		);

		add_settings_field(
			'client_id_0', // id
			'Client ID', // title
			array( $this, 'client_id_0_callback' ), // callback
			'php-oauth2-protocol-admin', // page
			'php_oauth2_protocol_setting_section' // section
		);

		add_settings_field(
			'client_secret_1', // id
			'Client Secret', // title
			array( $this, 'client_secret_1_callback' ), // callback
			'php-oauth2-protocol-admin', // page
			'php_oauth2_protocol_setting_section' // section
		);

		add_settings_field(
			'redirect_uri_2', // id
			'Redirect URI', // title
			array( $this, 'redirect_uri_2_callback' ), // callback
			'php-oauth2-protocol-admin', // page
			'php_oauth2_protocol_setting_section' // section
		);
	}

	public function php_oauth2_protocol_sanitize($input) {
		$sanitary_values = array();
		if ( isset( $input['client_id_0'] ) ) {
			$sanitary_values['client_id_0'] = sanitize_text_field( $input['client_id_0'] );
		}

		if ( isset( $input['client_secret_1'] ) ) {
			$sanitary_values['client_secret_1'] = sanitize_text_field( $input['client_secret_1'] );
		}

		if ( isset( $input['redirect_uri_2'] ) ) {
			$sanitary_values['redirect_uri_2'] = sanitize_text_field( $input['redirect_uri_2'] );
		}

		return $sanitary_values;
	}

	public function php_oauth2_protocol_section_info() {
		
	}

	public function client_id_0_callback() {
		printf(
			'<input class="regular-text" type="text" name="php_oauth2_protocol_option_name[client_id_0]" id="client_id_0" value="%s">',
			isset( $this->php_oauth2_protocol_options['client_id_0'] ) ? esc_attr( $this->php_oauth2_protocol_options['client_id_0']) : ''
		);
	}

	public function client_secret_1_callback() {
		printf(
			'<input class="regular-text" type="text" name="php_oauth2_protocol_option_name[client_secret_1]" id="client_secret_1" value="%s">',
			isset( $this->php_oauth2_protocol_options['client_secret_1'] ) ? esc_attr( $this->php_oauth2_protocol_options['client_secret_1']) : ''
		);
	}

	public function redirect_uri_2_callback() {
		printf(
			'<input class="regular-text" type="text" name="php_oauth2_protocol_option_name[redirect_uri_2]" id="redirect_uri_2" value="%s">',
			isset( $this->php_oauth2_protocol_options['redirect_uri_2'] ) ? esc_url( $this->php_oauth2_protocol_options['redirect_uri_2']) : ''
		);
	}

}

if ( is_admin() ){
	$php_oauth2_protocol = new PHPOAuthProtocol();
}

/* 
 * Retrieve this value with:
 * $php_oauth2_protocol_options = get_option( 'php_oauth2_protocol_option_name' ); // Array of All Options
 * $client_id_0 = $php_oauth2_protocol_options['client_id_0']; // Client ID
 * $client_secret_1 = $php_oauth2_protocol_options['client_secret_1']; // Client Secret
 * $redirect_uri_2 = $php_oauth2_protocol_options['redirect_uri_2']; // Redirect URI
 */


?>