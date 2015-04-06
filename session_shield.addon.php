<?php

/**
 * @file session_shield.addon.php
 * @author Kijin Sung <kijin@kijinsung.com>
 * @license LGPL v2.1 <http://www.gnu.org/licenses/lgpl-2.1.html>
 * @brief Session Shield addon
 * 
 * This addon improves session security by preventing XSS, session fixation,
 * and some types of sniffing attacks when SSL is only partially used.
 * It also adds a randomly generated token to every web page,
 * and checks the token whenever a POST request is made.
 * This helps prevent CSRF attacks.
 * 
 * This addon is experimental. It may cause problems in older versions of XE,
 * and when XE is used with SSO and/or virtual websites.
 */

if(!defined('__XE__')) exit;

require_once 'session_shield.class.php';

switch($called_position)
{
	case 'before_module_init':
		$shield = new Session_Shield();
		$shield->initialize();
		$shield->checkCSRFToken();
		return;
	
	case 'before_display_content':
		if(Context::getResponseMethod() != 'HTML') return;
		$shield = new Session_Shield();
		$shield->insertCSRFToken();
		return;
		
	default:
		return;
}
